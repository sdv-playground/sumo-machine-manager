//! QNX 7.1 default `SensorReader` — system metrics from procnto.
//!
//! Sources:
//! - `/proc/vm/stats` — memory pages (free, wired, kernel, anon, total)
//! - `sysconf(_SC_NPROCESSORS_ONLN)` — CPU count
//! - `clock_gettime(CLOCK_MONOTONIC)` — process uptime
//! - `/proc/1/usage` (future) — per-CPU idle ticks for utilization
//!
//! No temperature, voltage, or eMMC wear — those require board-specific
//! drivers (TMU resource manager, PMIC i2c, JEDEC devctl) that don't
//! ship in the default BSP.

use std::sync::Mutex;
use std::time::Instant;

use crate::{Sensor, SensorKind, SensorReader};

pub struct QnxSensorReader {
    process_start: Instant,
    #[allow(dead_code)]
    state: Mutex<()>,
}

impl QnxSensorReader {
    pub fn new() -> Self {
        Self {
            process_start: Instant::now(),
            state: Mutex::new(()),
        }
    }
}

impl Default for QnxSensorReader {
    fn default() -> Self {
        Self::new()
    }
}

impl SensorReader for QnxSensorReader {
    fn read(&self) -> Vec<Sensor> {
        let mut out = Vec::new();

        if let Some(n) = read_cpu_count() {
            out.push(Sensor {
                name: "host_cpu_count",
                help: "Number of online CPUs",
                kind: SensorKind::Gauge,
                value: n as f64,
                labels: vec![],
            });
        }

        out.push(Sensor {
            name: "host_uptime_seconds",
            help: "Seconds since this process started",
            kind: SensorKind::Gauge,
            value: self.process_start.elapsed().as_secs_f64(),
            labels: vec![],
        });

        out.extend(read_vm_stats());

        out
    }
}

fn read_cpu_count() -> Option<i64> {
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if n > 0 {
        Some(n)
    } else {
        None
    }
}

/// Parse `/proc/vm/stats` for memory metrics. Format is `key=value` or
/// `key=0xHEX (human)` per line. Values with `0x` prefix are in pages.
fn read_vm_stats() -> Vec<Sensor> {
    let content = match std::fs::read_to_string("/proc/vm/stats") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    parse_vm_stats(&content)
}

fn parse_vm_stats(content: &str) -> Vec<Sensor> {
    let mut out = Vec::new();
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) };
    let page_bytes: f64 = if page_size > 0 {
        page_size as f64
    } else {
        4096.0
    };

    let mut page_count: Option<u64> = None;
    let mut pages_free: Option<u64> = None;
    let mut pages_wired: Option<u64> = None;
    let mut pages_kernel: Option<u64> = None;
    let mut anon_count: Option<u64> = None;

    for line in content.lines() {
        let Some((key, val_str)) = line.split_once('=') else {
            continue;
        };
        let pages = parse_hex_or_dec(val_str);

        match key {
            "page_count" => page_count = pages,
            "pages_free" => pages_free = pages,
            "pages_wired" => pages_wired = pages,
            "pages_kernel" => pages_kernel = pages,
            "anon_count" => anon_count = pages,
            _ => {}
        }
    }

    if let Some(total) = page_count {
        out.push(Sensor {
            name: "host_memory_bytes",
            help: "Memory in bytes by state",
            kind: SensorKind::Gauge,
            value: total as f64 * page_bytes,
            labels: vec![("state", "total".into())],
        });
    }
    if let Some(free) = pages_free {
        out.push(Sensor {
            name: "host_memory_bytes",
            help: "Memory in bytes by state",
            kind: SensorKind::Gauge,
            value: free as f64 * page_bytes,
            labels: vec![("state", "free".into())],
        });
    }
    if let Some(total) = page_count {
        if let Some(free) = pages_free {
            out.push(Sensor {
                name: "host_memory_bytes",
                help: "Memory in bytes by state",
                kind: SensorKind::Gauge,
                value: (total - free) as f64 * page_bytes,
                labels: vec![("state", "used".into())],
            });
        }
    }
    if let Some(wired) = pages_wired {
        out.push(Sensor {
            name: "host_memory_bytes",
            help: "Memory in bytes by state",
            kind: SensorKind::Gauge,
            value: wired as f64 * page_bytes,
            labels: vec![("state", "wired".into())],
        });
    }
    if let Some(kernel) = pages_kernel {
        out.push(Sensor {
            name: "host_memory_bytes",
            help: "Memory in bytes by state",
            kind: SensorKind::Gauge,
            value: kernel as f64 * page_bytes,
            labels: vec![("state", "kernel".into())],
        });
    }
    if let Some(anon) = anon_count {
        out.push(Sensor {
            name: "host_memory_bytes",
            help: "Memory in bytes by state",
            kind: SensorKind::Gauge,
            value: anon as f64 * page_bytes,
            labels: vec![("state", "anonymous".into())],
        });
    }

    out
}

/// Parse `0xHEX (human)` or plain decimal. The `/proc/vm/stats` format
/// uses hex with a parenthesized human-readable suffix for page counts.
fn parse_hex_or_dec(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x") {
        let hex_part = rest.split_whitespace().next()?;
        u64::from_str_radix(hex_part, 16).ok()
    } else {
        s.split_whitespace().next()?.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_or_dec_works() {
        assert_eq!(parse_hex_or_dec("0xe0000 (3.500GB)"), Some(0xe0000));
        assert_eq!(parse_hex_or_dec("0xa9494 (2.644GB)"), Some(0xa9494));
        assert_eq!(parse_hex_or_dec("34"), Some(34));
        assert_eq!(parse_hex_or_dec("0x0 (0.000kB)"), Some(0));
    }

    #[test]
    fn parse_vm_stats_extracts_memory() {
        let input = "\
vm_aspace=34
vm_region=1576
page_count=0xe0000 (3.500GB)
anon_count=0x5c5d (92.363MB)
pages_free=0xa9494 (2.644GB)
pages_wired=0x4c35 (76.207MB)
pages_kernel=0x4c39 (76.222MB)
";
        let sensors = parse_vm_stats(input);
        let names: Vec<_> = sensors
            .iter()
            .map(|s| {
                let label = s.labels.first().map(|l| l.1.as_str()).unwrap_or("");
                (s.name, label)
            })
            .collect();
        assert!(names.contains(&("host_memory_bytes", "total")));
        assert!(names.contains(&("host_memory_bytes", "free")));
        assert!(names.contains(&("host_memory_bytes", "used")));
        assert!(names.contains(&("host_memory_bytes", "wired")));
        assert!(names.contains(&("host_memory_bytes", "kernel")));
        assert!(names.contains(&("host_memory_bytes", "anonymous")));

        let total = sensors
            .iter()
            .find(|s| s.labels.first().map(|l| l.1.as_str()) == Some("total"))
            .unwrap();
        // 0xe0000 pages * 4096 bytes = 3.5 GB
        assert_eq!(total.value, 0xe0000_u64 as f64 * 4096.0);
    }

    #[test]
    fn parse_vm_stats_handles_empty() {
        assert!(parse_vm_stats("").is_empty());
    }
}
