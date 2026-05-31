//! Host hardware metrics — Prometheus exposition with pluggable
//! `SensorReader` per platform.
//!
//! Lives at the workspace root so any host (vm-service, supernova, future
//! orchestrators) can embed it without dragging vm-* dependencies. No deps
//! on `vm-mgr`, `vm-service`, or `vm-devices`.
//!
//! ## Architecture
//!
//! ```text
//!   Hardware → SensorReader::read() → Vec<Sensor>
//!                                       │
//!                                       ▼
//!                          encode_prometheus(&[Sensor]) → text
//!                                       │
//!                                       ▼
//!                    GET /metrics  (axum router)
//! ```
//!
//! Each `SensorReader` impl decides its own scope:
//! - [`readers::LinuxSensorReader`] (Linux dev / generic Linux hosts):
//!   `/proc/stat`, `/sys/class/hwmon/*`, `/proc/meminfo`, `/proc/loadavg`.
//! - [`readers::QnxSensorReader`] (QNX 7.1 hosts): best-effort POSIX bits
//!   plus QNX-specific syscalls; thin until a target SoC ships hardware
//!   driver bindings.
//! - Production hardware readers (e.g. `S32g3SensorReader`) live **outside
//!   this crate**, in `supernova-machine-manager`. They implement the same
//!   trait and produce richer metric sets specific to the target board.
//!
//! ## Naming convention
//!
//! Standard Prometheus exposition rules:
//! - SI units in the metric name suffix (`_celsius`, `_volts`, `_bytes`,
//!   `_ratio`, `_seconds`, `_rpm`).
//! - Dimensions as labels (`cpu="0"`, `zone="soc"`, `rail="core"`).
//! - All gauges (no counters yet — heartbeat sequence numbers go through
//!   the device-transport channel, not Prometheus).

pub mod readers;

use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, routing::get, Router};

/// One sample emitted by a `SensorReader`. Maps 1:1 to one Prometheus
/// `<name>{<labels>} <value>` line.
#[derive(Debug, Clone)]
pub struct Sensor {
    /// Metric name including unit suffix (e.g. `host_temperature_celsius`).
    /// Must follow Prometheus naming: `[a-zA-Z_:][a-zA-Z0-9_:]*`.
    pub name: &'static str,
    /// Free-form description for `# HELP`. Same description for the same
    /// `name` across all samples — the encoder dedupes.
    pub help: &'static str,
    /// Metric kind. Today we only emit gauges; counters added when a
    /// real consumer needs them.
    pub kind: SensorKind,
    /// Numeric value. f64 because that's what Prometheus consumes; care
    /// is taken upstream to convert raw integer registers (e.g.
    /// millidegrees) into base SI units before reaching here.
    pub value: f64,
    /// Dimensions. Order is preserved on the wire.
    pub labels: Vec<(&'static str, String)>,
}

/// Prometheus metric type. `# TYPE <name> <kind>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorKind {
    Gauge,
    /// Reserved for future use — heartbeat sequence numbers, eMMC write
    /// counters, etc. The encoder already understands counter semantics.
    #[allow(dead_code)]
    Counter,
}

impl SensorKind {
    fn as_str(self) -> &'static str {
        match self {
            SensorKind::Gauge => "gauge",
            SensorKind::Counter => "counter",
        }
    }
}

/// Pluggable sensor source. One impl per platform / hardware target.
///
/// `read()` is called once per HTTP request. Implementations should be cheap
/// (~ms or less) — readers that do expensive work (e.g. `smartctl` shell
/// out) should cache and return the cache here.
pub trait SensorReader: Send + Sync {
    fn read(&self) -> Vec<Sensor>;
}

/// Returns the platform-default `SensorReader`. Linux scrapes `/sys` +
/// `/proc`; QNX uses `getloadavg` + `sysconf` best-effort; other platforms
/// return an empty reader.
pub fn default_reader() -> Arc<dyn SensorReader> {
    #[cfg(target_os = "linux")]
    {
        Arc::new(readers::LinuxSensorReader::new())
    }
    #[cfg(target_os = "nto")]
    {
        Arc::new(readers::QnxSensorReader::new())
    }
    #[cfg(not(any(target_os = "linux", target_os = "nto")))]
    {
        // Inline empty reader — no separate noop module per design.
        struct Empty;
        impl SensorReader for Empty {
            fn read(&self) -> Vec<Sensor> {
                Vec::new()
            }
        }
        tracing::warn!(
            "host-metrics: no platform-default reader for this target — /metrics will be empty"
        );
        Arc::new(Empty)
    }
}

/// Build an axum `Router` serving `GET /metrics` with the given reader.
///
/// Mount under whatever bind addr the host wants — typically a separate
/// port from any other API surface so scrapers don't need auth.
pub fn router(reader: Arc<dyn SensorReader>) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(reader)
}

async fn metrics_handler(State(reader): State<Arc<dyn SensorReader>>) -> impl IntoResponse {
    let sensors = reader.read();
    let body = encode_prometheus(&sensors);
    (
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}

/// Encode a list of `Sensor` samples as Prometheus exposition text.
///
/// Groups samples by `name`, emits `# HELP` + `# TYPE` once per group,
/// then one line per sample. Non-finite values (NaN, infinities) are
/// skipped — Prometheus `Nan` and `+Inf` parse but they cause grief with
/// most dashboards, and the silent skip lets readers be sloppy without
/// breaking scrapes.
pub fn encode_prometheus(sensors: &[Sensor]) -> String {
    use std::collections::BTreeMap;

    // Stable iteration order: BTreeMap by name. Within a group, samples
    // appear in input order.
    let mut groups: BTreeMap<&str, Vec<&Sensor>> = BTreeMap::new();
    for s in sensors {
        groups.entry(s.name).or_default().push(s);
    }

    let mut out = String::with_capacity(sensors.len() * 64);
    for (name, samples) in groups {
        // Pick the first sample's help/kind as canonical for the group.
        // Callers should be consistent; we don't double-check.
        let head = samples[0];
        out.push_str("# HELP ");
        out.push_str(name);
        out.push(' ');
        out.push_str(head.help);
        out.push('\n');
        out.push_str("# TYPE ");
        out.push_str(name);
        out.push(' ');
        out.push_str(head.kind.as_str());
        out.push('\n');

        for s in samples {
            if !s.value.is_finite() {
                continue;
            }
            out.push_str(name);
            if !s.labels.is_empty() {
                out.push('{');
                for (i, (k, v)) in s.labels.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(k);
                    out.push_str("=\"");
                    // Escape backslash, double-quote, newline per Prom spec.
                    for ch in v.chars() {
                        match ch {
                            '\\' => out.push_str("\\\\"),
                            '"' => out.push_str("\\\""),
                            '\n' => out.push_str("\\n"),
                            c => out.push(c),
                        }
                    }
                    out.push('"');
                }
                out.push('}');
            }
            out.push(' ');
            // Use {} not {:.6} — let f64::to_string pick width, drops
            // unnecessary trailing zeros and uses scientific for tiny / huge.
            out.push_str(&s.value.to_string());
            out.push('\n');
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_emits_help_and_type_once_per_group() {
        let sensors = vec![
            Sensor {
                name: "host_temperature_celsius",
                help: "Hardware temperature",
                kind: SensorKind::Gauge,
                value: 45.0,
                labels: vec![("zone", "soc".into())],
            },
            Sensor {
                name: "host_temperature_celsius",
                help: "Hardware temperature",
                kind: SensorKind::Gauge,
                value: 38.5,
                labels: vec![("zone", "board".into())],
            },
        ];
        let out = encode_prometheus(&sensors);
        assert_eq!(out.matches("# HELP host_temperature_celsius").count(), 1);
        assert_eq!(
            out.matches("# TYPE host_temperature_celsius gauge").count(),
            1
        );
        assert!(out.contains("host_temperature_celsius{zone=\"soc\"} 45"));
        assert!(out.contains("host_temperature_celsius{zone=\"board\"} 38.5"));
    }

    #[test]
    fn encode_emits_no_labels_block_for_unlabeled_metric() {
        let sensors = vec![Sensor {
            name: "host_cpu_count",
            help: "Number of online CPUs",
            kind: SensorKind::Gauge,
            value: 8.0,
            labels: vec![],
        }];
        let out = encode_prometheus(&sensors);
        assert!(out.contains("\nhost_cpu_count 8\n"), "got: {out:?}");
    }

    #[test]
    fn encode_skips_non_finite_values() {
        let sensors = vec![
            Sensor {
                name: "x",
                help: "h",
                kind: SensorKind::Gauge,
                value: f64::NAN,
                labels: vec![],
            },
            Sensor {
                name: "x",
                help: "h",
                kind: SensorKind::Gauge,
                value: f64::INFINITY,
                labels: vec![],
            },
            Sensor {
                name: "x",
                help: "h",
                kind: SensorKind::Gauge,
                value: 1.0,
                labels: vec![],
            },
        ];
        let out = encode_prometheus(&sensors);
        // Only the finite sample produces a metric line.
        let metric_lines: Vec<_> = out
            .lines()
            .filter(|l| l.starts_with("x"))
            .filter(|l| !l.starts_with("# "))
            .collect();
        assert_eq!(metric_lines.len(), 1);
        assert!(metric_lines[0].ends_with(" 1"));
    }

    #[test]
    fn encode_groups_sort_alphabetically_by_name() {
        let sensors = vec![
            Sensor {
                name: "z_metric",
                help: "z",
                kind: SensorKind::Gauge,
                value: 1.0,
                labels: vec![],
            },
            Sensor {
                name: "a_metric",
                help: "a",
                kind: SensorKind::Gauge,
                value: 2.0,
                labels: vec![],
            },
        ];
        let out = encode_prometheus(&sensors);
        let a_pos = out.find("# HELP a_metric").unwrap();
        let z_pos = out.find("# HELP z_metric").unwrap();
        assert!(a_pos < z_pos);
    }

    #[test]
    fn encode_escapes_special_chars_in_label_values() {
        let sensors = vec![Sensor {
            name: "x",
            help: "h",
            kind: SensorKind::Gauge,
            value: 1.0,
            labels: vec![("k", "back\\slash \"quote\" line\nbreak".into())],
        }];
        let out = encode_prometheus(&sensors);
        // \ → \\, " → \", \n → \n (literal backslash-n)
        assert!(
            out.contains(r#"k="back\\slash \"quote\" line\nbreak""#),
            "got: {out:?}"
        );
    }

    #[test]
    fn encode_empty_input_produces_empty_output() {
        assert_eq!(encode_prometheus(&[]), "");
    }

    #[test]
    fn sensor_kind_as_str_matches_prometheus_keywords() {
        assert_eq!(SensorKind::Gauge.as_str(), "gauge");
        assert_eq!(SensorKind::Counter.as_str(), "counter");
    }
}
