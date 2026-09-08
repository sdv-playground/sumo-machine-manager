//! Per-VM health status — what gets surfaced via the API.
//!
//! Derived from a combination of process state (is the qvm/qemu PID still
//! alive?) and the latest heartbeat snapshot read from the device-transport
//! channel. The legacy `HealthMonitor` (POSIX `std::fs::read` on the
//! ivshmem region) is gone — `VmManager` now owns a `HeartbeatDevice` per
//! VM and reads from it directly.

use serde::Serialize;

/// Coarse-grained health classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    /// Process is up but no fresh heartbeat yet (or guest reports `Booting`).
    Starting,
    /// Process is up and guest reports `Running` with a non-stale heartbeat.
    Running,
    /// Heartbeat is stale (seq not advancing) or guest reports `Degraded`.
    Unhealthy,
    /// Guest reports `ShuttingDown`.
    ShuttingDown,
    /// Process is not running.
    Stopped,
    /// State could not be determined (no monitor configured, or read error).
    /// Currently unused — `read_health` returns `Stopped` / `Starting` /
    /// `Running` exhaustively. Kept in the API contract for forward compat.
    #[allow(dead_code)]
    Unknown,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Starting => write!(f, "starting"),
            HealthStatus::Running => write!(f, "running"),
            HealthStatus::Unhealthy => write!(f, "unhealthy"),
            HealthStatus::ShuttingDown => write!(f, "shutting_down"),
            HealthStatus::Stopped => write!(f, "stopped"),
            HealthStatus::Unknown => write!(f, "unknown"),
        }
    }
}

/// Detailed health snapshot — adds raw guest-state and seq counter so SOVD
/// callers can show finer-grained info than just `HealthStatus`.
#[derive(Debug, Clone, Serialize)]
pub struct HealthDetail {
    pub status: HealthStatus,
    /// Guest-reported state code (0=Booting, 1=Running, 2=Degraded, 3=ShuttingDown).
    /// `None` when no heartbeat has been observed yet.
    pub guest_state: Option<u32>,
    /// Heartbeat sequence number — host uses this to detect liveness across polls.
    pub hb_seq: Option<u32>,
    /// Boot-id randomly generated per guest lifetime. Distinct value across
    /// stop/start cycles, so flash orchestrators can definitively tell that
    /// "the heartbeat I'm reading now is from a fresh boot, not stale shmem
    /// data from the previous lifetime". The qvm-shmem region persists
    /// across guest lifetimes, so hb_seq alone is NOT a reliable freshness
    /// signal.
    pub boot_id: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_strings_match_serialization() {
        for (s, want) in [
            (HealthStatus::Starting, "starting"),
            (HealthStatus::Running, "running"),
            (HealthStatus::Unhealthy, "unhealthy"),
            (HealthStatus::ShuttingDown, "shutting_down"),
            (HealthStatus::Stopped, "stopped"),
            (HealthStatus::Unknown, "unknown"),
        ] {
            assert_eq!(format!("{s}"), want);
        }
    }
}
