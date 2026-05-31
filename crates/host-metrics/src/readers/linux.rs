//! Linux `SensorReader` — scrapes generic kernel interfaces.
//!
//! All sources are best-effort: missing files / unreadable devices simply
//! don't produce metrics, rather than causing the reader to fail. A scrape
//! of `/metrics` on a host with no hwmon devices returns CPU usage +
//! memory + load average and that's it; that's still useful and matches
//! what `node_exporter` does.
//!
//! ## Sources
//!
//! - **CPU usage** from `/proc/stat`. We compute the ratio of non-idle to
//!   total ticks since the previous read, so the reader is stateful: the
//!   first read after construction returns 0.0 (no baseline), subsequent
//!   reads show actual usage.
//! - **Temperatures, voltages, fans** from `/sys/class/hwmon/*/`:
//!   `temp*_input` (millidegrees), `in*_input` (millivolts), `fan*_input`
//!   (RPM). Labels come from sibling `*_label` files when present.
//! - **Memory** from `/proc/meminfo` — `MemTotal`, `MemFree`, `MemAvailable`.
//! - **Load average** from `/proc/loadavg` — three samples: 1m, 5m, 15m.
//!
//! Hardware-specific things (eMMC SMART wear, board-specific i2c sensors,
//! per-rail current monitors) live outside this crate, in
//! `supernova-machine-manager`'s production reader. The default here is
//! deliberately generic.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::{Sensor, SensorKind, SensorReader};

/// Linux default reader. Holds CPU usage state across reads.
pub struct LinuxSensorReader {
    cpu_state: Mutex<Option<CpuTickSnapshot>>,
}

impl LinuxSensorReader {
    pub fn new() -> Self {
        Self {
            cpu_state: Mutex::new(None),
        }
    }
}

impl Default for LinuxSensorReader {
    fn default() -> Self {
        Self::new()
    }
}

impl SensorReader for LinuxSensorReader {
    fn read(&self) -> Vec<Sensor> {
        let mut out = Vec::new();
        out.extend(self.read_cpu());
        out.extend(read_meminfo());
        out.extend(read_loadavg());
        out.extend(read_hwmon());
        out
    }
}

impl LinuxSensorReader {
    fn read_cpu(&self) -> Vec<Sensor> {
        let content = match std::fs::read_to_string("/proc/stat") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let snapshot = parse_proc_stat(&content);

        let mut state = self.cpu_state.lock().expect("cpu_state poisoned");
        let prev = state.replace(snapshot.clone());
        let Some(prev) = prev else {
            // First read — no baseline yet. Emit cpu count but no usage.
            return vec![Sensor {
                name: "host_cpu_count",
                help: "Number of online CPUs",
                kind: SensorKind::Gauge,
                value: snapshot.cpus.len() as f64,
                labels: vec![],
            }];
        };

        let mut samples = Vec::with_capacity(snapshot.cpus.len() + 1);
        samples.push(Sensor {
            name: "host_cpu_count",
            help: "Number of online CPUs",
            kind: SensorKind::Gauge,
            value: snapshot.cpus.len() as f64,
            labels: vec![],
        });
        for (i, cur) in snapshot.cpus.iter().enumerate() {
            let Some(p) = prev.cpus.get(i) else { continue };
            if let Some(usage) = cur.usage_ratio_since(p) {
                samples.push(Sensor {
                    name: "host_cpu_usage_ratio",
                    help: "CPU usage 0..1 since previous scrape",
                    kind: SensorKind::Gauge,
                    value: usage,
                    labels: vec![("cpu", i.to_string())],
                });
            }
        }
        samples
    }
}

// ---------------------------------------------------------------------------
// /proc/stat — pure parser + snapshot diff
// ---------------------------------------------------------------------------

/// One CPU's tick counters from `/proc/stat`. Names match the kernel docs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CpuTicks {
    user: u64,
    nice: u64,
    system: u64,
    idle: u64,
    iowait: u64,
    irq: u64,
    softirq: u64,
    steal: u64,
}

impl CpuTicks {
    fn total(&self) -> u64 {
        self.user
            + self.nice
            + self.system
            + self.idle
            + self.iowait
            + self.irq
            + self.softirq
            + self.steal
    }

    fn busy(&self) -> u64 {
        self.total() - self.idle - self.iowait
    }

    /// Ratio in [0.0, 1.0] of busy ticks between two snapshots.
    /// Returns `None` if `self` is not strictly later than `prev` (e.g.
    /// counter wrap, identical reads).
    fn usage_ratio_since(&self, prev: &Self) -> Option<f64> {
        let total_diff = self.total().checked_sub(prev.total())?;
        if total_diff == 0 {
            return None;
        }
        let busy_diff = self.busy().checked_sub(prev.busy())?;
        Some(busy_diff as f64 / total_diff as f64)
    }
}

#[derive(Debug, Clone)]
struct CpuTickSnapshot {
    /// Per-CPU samples in CPU-index order. The aggregate "cpu" line from
    /// /proc/stat is not stored — we compute aggregate metrics off the
    /// per-CPU samples if needed.
    cpus: Vec<CpuTicks>,
}

fn parse_proc_stat(content: &str) -> CpuTickSnapshot {
    let mut cpus = Vec::new();
    for line in content.lines() {
        // Skip the aggregate "cpu " line (no digit after "cpu"); pick up
        // "cpu0", "cpu1", ... which have a digit after the prefix.
        let Some(rest) = line.strip_prefix("cpu") else {
            continue;
        };
        if !rest
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            continue;
        }
        let mut parts = rest.split_ascii_whitespace();
        let _idx = parts.next(); // cpu0, cpu1, ...
        let nums: Vec<u64> = parts.filter_map(|s| s.parse::<u64>().ok()).collect();
        if nums.len() >= 8 {
            cpus.push(CpuTicks {
                user: nums[0],
                nice: nums[1],
                system: nums[2],
                idle: nums[3],
                iowait: nums[4],
                irq: nums[5],
                softirq: nums[6],
                steal: nums[7],
            });
        }
    }
    CpuTickSnapshot { cpus }
}

// ---------------------------------------------------------------------------
// /proc/meminfo — parser + sensor emission
// ---------------------------------------------------------------------------

fn read_meminfo() -> Vec<Sensor> {
    let content = match std::fs::read_to_string("/proc/meminfo") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    parse_meminfo(&content)
}

fn parse_meminfo(content: &str) -> Vec<Sensor> {
    fn extract(content: &str, key: &str) -> Option<u64> {
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix(key) {
                let rest = rest.trim_start_matches(':').trim();
                let mut parts = rest.split_ascii_whitespace();
                let val_str = parts.next()?;
                let val: u64 = val_str.parse().ok()?;
                // /proc/meminfo always reports in kB.
                return Some(val * 1024);
            }
        }
        None
    }

    let mut out = Vec::new();
    if let Some(b) = extract(content, "MemTotal") {
        out.push(Sensor {
            name: "host_memory_bytes",
            help: "Memory in bytes by state",
            kind: SensorKind::Gauge,
            value: b as f64,
            labels: vec![("state", "total".into())],
        });
    }
    if let Some(b) = extract(content, "MemFree") {
        out.push(Sensor {
            name: "host_memory_bytes",
            help: "Memory in bytes by state",
            kind: SensorKind::Gauge,
            value: b as f64,
            labels: vec![("state", "free".into())],
        });
    }
    if let Some(b) = extract(content, "MemAvailable") {
        out.push(Sensor {
            name: "host_memory_bytes",
            help: "Memory in bytes by state",
            kind: SensorKind::Gauge,
            value: b as f64,
            labels: vec![("state", "available".into())],
        });
    }
    out
}

// ---------------------------------------------------------------------------
// /proc/loadavg — parser + sensor emission
// ---------------------------------------------------------------------------

fn read_loadavg() -> Vec<Sensor> {
    let content = match std::fs::read_to_string("/proc/loadavg") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    parse_loadavg(&content)
}

fn parse_loadavg(content: &str) -> Vec<Sensor> {
    let parts: Vec<&str> = content.split_ascii_whitespace().take(3).collect();
    let labels = ["1m", "5m", "15m"];
    parts
        .iter()
        .zip(labels.iter())
        .filter_map(|(s, &period)| {
            s.parse::<f64>().ok().map(|v| Sensor {
                name: "host_load_average",
                help: "System load average over period",
                kind: SensorKind::Gauge,
                value: v,
                labels: vec![("period", period.into())],
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// /sys/class/hwmon/* — directory walk + sensor emission
// ---------------------------------------------------------------------------

fn read_hwmon() -> Vec<Sensor> {
    let hwmon_dir = Path::new("/sys/class/hwmon");
    let entries = match std::fs::read_dir(hwmon_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let chip_name = read_label_file(&path.join("name")).unwrap_or_else(|| "unknown".into());
        out.extend(scrape_hwmon_dir(&path, &chip_name));
    }
    out
}

/// Walk one `/sys/class/hwmon/hwmonN/` directory, emitting samples for
/// every `temp*_input`, `in*_input`, `fan*_input` it finds.
fn scrape_hwmon_dir(dir: &Path, chip: &str) -> Vec<Sensor> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };

        if let Some((kind, idx)) = parse_hwmon_input(name_str) {
            let path = entry.path();
            let raw = match std::fs::read_to_string(&path) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let raw_value: i64 = match raw.trim().parse() {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Convert kernel raw to SI:
            // - temp*_input is millidegrees → °C / 1000
            // - in*_input is millivolts     → V  / 1000
            // - fan*_input is RPM           → as-is
            let label_path = dir.join(format!("{kind}{idx}_label"));
            let label = read_label_file(&label_path).unwrap_or_else(|| format!("{kind}{idx}"));

            let sensor = match kind {
                "temp" => Some(Sensor {
                    name: "host_temperature_celsius",
                    help: "Hardware temperature",
                    kind: SensorKind::Gauge,
                    value: raw_value as f64 / 1000.0,
                    labels: vec![("chip", chip.into()), ("zone", label)],
                }),
                "in" => Some(Sensor {
                    name: "host_voltage_volts",
                    help: "Power-rail voltage",
                    kind: SensorKind::Gauge,
                    value: raw_value as f64 / 1000.0,
                    labels: vec![("chip", chip.into()), ("rail", label)],
                }),
                "fan" => Some(Sensor {
                    name: "host_fan_rpm",
                    help: "Fan rotation rate",
                    kind: SensorKind::Gauge,
                    value: raw_value as f64,
                    labels: vec![("chip", chip.into()), ("fan", label)],
                }),
                _ => None,
            };
            if let Some(s) = sensor {
                out.push(s);
            }
        }
    }
    out
}

/// Parse e.g. `"temp1_input"` into `("temp", 1)`. Anything else returns
/// `None` so the caller skips it.
fn parse_hwmon_input(name: &str) -> Option<(&'static str, u32)> {
    for prefix in ["temp", "in", "fan"] {
        if let Some(rest) = name.strip_prefix(prefix) {
            if let Some(num_str) = rest.strip_suffix("_input") {
                if let Ok(idx) = num_str.parse::<u32>() {
                    let static_prefix: &'static str = match prefix {
                        "temp" => "temp",
                        "in" => "in",
                        "fan" => "fan",
                        _ => unreachable!(),
                    };
                    return Some((static_prefix, idx));
                }
            }
        }
    }
    None
}

fn read_label_file(path: &PathBuf) -> Option<String> {
    let raw = std::fs::read_to_string(path).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- /proc/stat ----

    #[test]
    fn parse_proc_stat_skips_aggregate_line() {
        let input = "\
cpu  1 2 3 4 5 6 7 8 0 0
cpu0 1 2 3 4 5 6 7 8
cpu1 9 10 11 12 13 14 15 16
intr 0
";
        let snap = parse_proc_stat(input);
        assert_eq!(snap.cpus.len(), 2);
        assert_eq!(snap.cpus[0].user, 1);
        assert_eq!(snap.cpus[1].user, 9);
    }

    #[test]
    fn parse_proc_stat_handles_extra_columns() {
        // Modern kernels include guest/guest_nice after steal.
        let input = "cpu0 1 2 3 4 5 6 7 8 9 10\n";
        let snap = parse_proc_stat(input);
        assert_eq!(snap.cpus.len(), 1);
        assert_eq!(snap.cpus[0].steal, 8);
    }

    #[test]
    fn cpu_ticks_usage_ratio_basic() {
        let prev = CpuTicks {
            user: 0,
            nice: 0,
            system: 0,
            idle: 100,
            iowait: 0,
            irq: 0,
            softirq: 0,
            steal: 0,
        };
        let cur = CpuTicks {
            user: 50,
            nice: 0,
            system: 0,
            idle: 150,
            iowait: 0,
            irq: 0,
            softirq: 0,
            steal: 0,
        };
        // total diff = 100, busy diff = 50 → 50%.
        assert!((cur.usage_ratio_since(&prev).unwrap() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn cpu_ticks_usage_ratio_returns_none_on_no_progress() {
        let snap = CpuTicks {
            user: 1,
            nice: 1,
            system: 1,
            idle: 1,
            iowait: 0,
            irq: 0,
            softirq: 0,
            steal: 0,
        };
        assert_eq!(snap.usage_ratio_since(&snap), None);
    }

    #[test]
    fn cpu_ticks_usage_ratio_returns_none_on_counter_regression() {
        let prev = CpuTicks {
            user: 100,
            nice: 0,
            system: 0,
            idle: 0,
            iowait: 0,
            irq: 0,
            softirq: 0,
            steal: 0,
        };
        let cur = CpuTicks {
            user: 50,
            nice: 0,
            system: 0,
            idle: 0,
            iowait: 0,
            irq: 0,
            softirq: 0,
            steal: 0,
        };
        // checked_sub returns None on regression.
        assert_eq!(cur.usage_ratio_since(&prev), None);
    }

    // ---- /proc/meminfo ----

    #[test]
    fn parse_meminfo_emits_total_free_available() {
        let input = "\
MemTotal:       16384000 kB
MemFree:         8000000 kB
MemAvailable:   12000000 kB
Buffers:           50000 kB
";
        let s = parse_meminfo(input);
        assert_eq!(s.len(), 3);
        // 16384000 kB → 16777216000 bytes
        let total = s.iter().find(|x| x.labels[0].1 == "total").unwrap();
        assert_eq!(total.value, 16384000.0 * 1024.0);
        assert_eq!(total.name, "host_memory_bytes");
    }

    #[test]
    fn parse_meminfo_handles_missing_keys() {
        let input = "MemTotal: 1024 kB\n";
        let s = parse_meminfo(input);
        assert_eq!(s.len(), 1);
    }

    // ---- /proc/loadavg ----

    #[test]
    fn parse_loadavg_emits_three_samples() {
        let s = parse_loadavg("0.42 0.30 0.25 1/100 1234\n");
        assert_eq!(s.len(), 3);
        let values: Vec<f64> = s.iter().map(|x| x.value).collect();
        assert_eq!(values, vec![0.42, 0.30, 0.25]);
    }

    #[test]
    fn parse_loadavg_partial_input() {
        let s = parse_loadavg("0.5 1.0\n");
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn parse_loadavg_garbage_input() {
        let s = parse_loadavg("not a load average\n");
        assert!(s.is_empty());
    }

    // ---- hwmon name parsing ----

    #[test]
    fn parse_hwmon_input_temp() {
        assert_eq!(parse_hwmon_input("temp1_input"), Some(("temp", 1)));
        assert_eq!(parse_hwmon_input("temp42_input"), Some(("temp", 42)));
    }

    #[test]
    fn parse_hwmon_input_in() {
        assert_eq!(parse_hwmon_input("in0_input"), Some(("in", 0)));
        assert_eq!(parse_hwmon_input("in12_input"), Some(("in", 12)));
    }

    #[test]
    fn parse_hwmon_input_fan() {
        assert_eq!(parse_hwmon_input("fan1_input"), Some(("fan", 1)));
    }

    #[test]
    fn parse_hwmon_input_rejects_other_files() {
        assert_eq!(parse_hwmon_input("name"), None);
        assert_eq!(parse_hwmon_input("temp1_label"), None);
        assert_eq!(parse_hwmon_input("temp1_max"), None);
        assert_eq!(parse_hwmon_input("curr1_input"), None); // current — not handled yet
        assert_eq!(parse_hwmon_input("temp_input"), None); // missing index
    }

    // ---- end-to-end ----

    #[test]
    fn linux_reader_first_call_returns_cpu_count_only_no_usage() {
        // /proc/stat reads succeed (we're on Linux in CI). First call has
        // no baseline so usage isn't emitted; cpu_count is.
        let r = LinuxSensorReader::new();
        let samples = r.read();
        let names: Vec<&str> = samples.iter().map(|s| s.name).collect();
        assert!(names.contains(&"host_cpu_count"));
        // No host_cpu_usage_ratio on first call.
        assert!(!samples.iter().any(|s| s.name == "host_cpu_usage_ratio"));
    }

    #[test]
    fn linux_reader_second_call_yields_cpu_usage() {
        let r = LinuxSensorReader::new();
        let _ = r.read();
        // Generate a tiny bit of CPU work between reads so usage isn't 0
        // (not strictly required for the test, but matches reality).
        std::thread::sleep(std::time::Duration::from_millis(20));
        let samples = r.read();
        assert!(samples.iter().any(|s| s.name == "host_cpu_usage_ratio"));
    }
}
