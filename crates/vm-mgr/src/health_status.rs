//! Per-VM health status — what gets surfaced via the API.
//!
//! Derived from a combination of process state (is the qvm/qemu PID still
//! alive?) and the latest heartbeat snapshot read from the device-transport
//! channel. The legacy `HealthMonitor` (POSIX `std::fs::read` on the
//! ivshmem region) is gone — `VmManager` now owns a `HeartbeatDevice` per
//! VM and reads from it directly.

use serde::Serialize;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Coarse-grained health classification.
///
/// Two invariants an observer may rely on:
///
/// * **`Failed` is terminal.** Nothing will change without an action (a start,
///   a re-flash, an operator). Waiting for a `Failed` VM to become `Running`
///   burns the whole timeout for no information. Every other non-`Running`
///   status may still resolve on its own.
/// * **No status encodes a deadline.** "Started but not up" is `Starting` held
///   for too long — the *observer* decides what "too long" is, from
///   [`HealthDetail::for_ms`]. Wiring a threshold in here would put the policy
///   in the wrong process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    /// Process is up but no fresh heartbeat yet (or guest reports `Booting`).
    Starting,
    /// Process is up and guest reports `Running` with a non-stale heartbeat.
    Running,
    /// Heartbeat is stale (seq not advancing) or guest reports `Degraded`.
    Unhealthy,
    /// Guest reports `ShuttingDown`. Transient by nature — the process is still
    /// alive, so this is NOT `Stopped`, and it is not a fault either.
    ShuttingDown,
    /// Process is not running, and that is what was asked for (an operator stop,
    /// or nothing ever asked it to start). Not a fault.
    Stopped,
    /// Process is not running and nobody asked for that: the launch was refused
    /// (pre-launch verify, missing kernel), the runner failed to spawn it, or
    /// the process exited on its own. [`HealthDetail::reason`] says which.
    ///
    /// The state that did not exist before — a failed guest reported `Stopped`,
    /// indistinguishable from a deliberately-stopped one, so an orchestrator had
    /// to wait out its full timeout to learn the difference.
    Failed,
    /// State could not be determined: the process is up but there is no
    /// heartbeat device to ask (no `health` device declared, or no device
    /// transport configured). Reported `Running` before, which was a guess —
    /// process liveness is not guest liveness.
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
            HealthStatus::Failed => write!(f, "failed"),
            HealthStatus::Unknown => write!(f, "unknown"),
        }
    }
}

impl HealthStatus {
    /// True when the VM process is not running. `Failed` and `Stopped` differ
    /// only in whether that was intended — both are down.
    pub fn is_down(self) -> bool {
        matches!(self, HealthStatus::Stopped | HealthStatus::Failed)
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
    /// How long this VM has continuously held `status`, in milliseconds,
    /// measured on the host's MONOTONIC clock.
    ///
    /// This is the field a deadline must be computed from, for two reasons:
    /// the host's `CLOCK_REALTIME` can step (the safe-time floor ratchets as
    /// signed material is accepted, and gPTP can discipline it), and an
    /// observer that polls cannot otherwise tell a guest that has been
    /// `Starting` for 2 seconds from one that has been `Starting` for 10
    /// minutes. Publishing the clock instead of a verdict keeps the threshold
    /// with the policy — see [`HealthStatus`].
    pub for_ms: u64,
    /// Wall-clock instant the VM entered `status` (UNIX seconds). For log
    /// correlation and display only — never for deadlines (see `for_ms`).
    /// `None` if the host clock was before the epoch when the transition
    /// happened (an unset RTC early in boot).
    pub since_unix_secs: Option<u64>,
    /// Why the VM is in `status`, when the status alone doesn't say: the verify
    /// refusal, the missing kernel path, "no active bank selected", "operator
    /// stop requested", "process exited without a stop request". `None` means
    /// nothing was recorded — a VM that simply came up and stayed up.
    pub reason: Option<String>,
}

/// Per-VM observed lifecycle record: the current [`HealthStatus`], when it was
/// first observed, and why.
///
/// Held in RAM inside `ManagedVm` and deliberately **never persisted**. Every
/// field is a statement about the current host process lifetime, so a reboot
/// must forget it — a durable copy could only ever be stale, and there is
/// nothing here a power cycle should carry forward.
///
/// `read_health` computes the status from process state + heartbeat as before;
/// this record supplies the two things that computation cannot see on its own:
/// the *reason* (known only at the moment the decision was taken, inside
/// `start_vm` / `initiate_stop`) and the *duration* (only observable by
/// remembering the previous poll).
pub(crate) struct Lifecycle {
    status: HealthStatus,
    since: Instant,
    since_wall: SystemTime,
    reason: Option<String>,
    /// Set when the recorded `reason` describes a failure rather than an
    /// intended state, which is what turns a down VM into `Failed` instead of
    /// `Stopped`.
    failed: bool,
    /// True from `initiate_stop` until the next successful start. Without it,
    /// "the operator stopped it" and "it died" are the same observation: no
    /// process, no handle.
    stop_requested: bool,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            // Nothing has been asked of this VM yet: down, and that is fine.
            status: HealthStatus::Stopped,
            since: Instant::now(),
            since_wall: SystemTime::now(),
            reason: None,
            failed: false,
            stop_requested: false,
        }
    }
}

impl Lifecycle {
    /// Record why the VM is in the state it is. `failed` distinguishes a fault
    /// (launch refused, spawn failed, unexpected exit) from an intended state
    /// (no bank selected, operator stop).
    pub(crate) fn note(&mut self, reason: impl Into<String>, failed: bool) {
        self.reason = Some(reason.into());
        self.failed = failed;
    }

    /// A stop was requested — a subsequent "not running" is `Stopped`, not
    /// `Failed`. Clears any earlier failure: the operator's intent supersedes
    /// whatever the previous lifetime ended with.
    pub(crate) fn note_stop_requested(&mut self) {
        self.stop_requested = true;
        self.failed = false;
        self.reason = Some("stop requested".to_string());
    }

    /// A launch succeeded — the record starts clean for the new lifetime.
    pub(crate) fn note_started(&mut self) {
        self.stop_requested = false;
        self.failed = false;
        self.reason = None;
    }

    pub(crate) fn stop_requested(&self) -> bool {
        self.stop_requested
    }

    /// Whether a down VM should report [`HealthStatus::Failed`].
    pub(crate) fn is_failed(&self) -> bool {
        self.failed
    }

    /// Stamp `status` onto the record and return the observation to publish.
    /// The `since` clock restarts only when the status actually changes, so
    /// `for_ms` measures the current state and not the time since the last
    /// poll.
    pub(crate) fn observe(&mut self, status: HealthStatus, now: Instant) -> (u64, Option<u64>) {
        if status != self.status {
            self.status = status;
            self.since = now;
            self.since_wall = SystemTime::now();
        }
        let for_ms = now.saturating_duration_since(self.since).as_millis() as u64;
        let since_unix_secs = self
            .since_wall
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs());
        (for_ms, since_unix_secs)
    }

    pub(crate) fn reason(&self) -> Option<String> {
        self.reason.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn display_strings_match_serialization() {
        for (s, want) in [
            (HealthStatus::Starting, "starting"),
            (HealthStatus::Running, "running"),
            (HealthStatus::Unhealthy, "unhealthy"),
            (HealthStatus::ShuttingDown, "shutting_down"),
            (HealthStatus::Stopped, "stopped"),
            (HealthStatus::Failed, "failed"),
            (HealthStatus::Unknown, "unknown"),
        ] {
            assert_eq!(format!("{s}"), want);
            // The wire form is the Display form — component-mgr matches on the
            // serialized string, so a rename_all slip here is a silent
            // cross-crate break.
            assert_eq!(serde_json::to_string(&s).unwrap(), format!("\"{want}\""));
        }
    }

    #[test]
    fn since_clock_restarts_only_on_a_real_transition() {
        let mut lc = Lifecycle::default();
        let t0 = Instant::now();

        // Two polls in the same state: for_ms grows.
        let (a, _) = lc.observe(HealthStatus::Starting, t0);
        let (b, _) = lc.observe(HealthStatus::Starting, t0 + Duration::from_secs(5));
        assert_eq!(a, 0);
        assert_eq!(b, 5_000, "for_ms must measure the STATE, not the poll gap");

        // A transition resets it.
        let (c, _) = lc.observe(HealthStatus::Running, t0 + Duration::from_secs(5));
        assert_eq!(c, 0);
    }

    #[test]
    fn stop_request_supersedes_an_earlier_failure() {
        let mut lc = Lifecycle::default();
        lc.note("pre-launch verify failed", true);
        assert!(lc.is_failed());

        lc.note_stop_requested();
        assert!(!lc.is_failed(), "an operator stop is not a fault");
        assert!(lc.stop_requested());

        // ...and a successful start clears everything for the new lifetime.
        lc.note_started();
        assert!(!lc.is_failed());
        assert!(!lc.stop_requested());
        assert_eq!(lc.reason(), None);
    }
}
