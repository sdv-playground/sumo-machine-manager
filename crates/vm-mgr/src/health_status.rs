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

/// What the VM is *supposed* to be doing — the declared-intent axis, orthogonal
/// to the observed [`HealthStatus`].
///
/// Without it, "down" is one word for three unrelated situations: an operator
/// stopped it, nothing ever asked it to run, or it should be running and is not.
/// An observer that cannot tell those apart cannot decide whether a node is
/// healthy, which is why every consumer grew its own guess.
///
/// Derived from the **actions actually taken**, never from config. `auto_start`
/// is only a trigger, and it is acted on outside this crate (the standalone
/// `vm-service` binary, supernova's own `auto_start_vms` toggle) — a host
/// configured not to start anything would make a config-derived intent lie on
/// its very first read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedState {
    /// Nothing has asked this VM to run or to stop. **Not** the same as
    /// `Stopped`, and the distinction is load-bearing: with `auto_start_vms:
    /// false`, or with an external start orchestrator, no action is ever
    /// recorded — and if that defaulted to `Stopped` the pair
    /// (expected stopped, observed stopped) would read as "healthy and settled"
    /// for a node whose starter died. `Unset` yields no verdict at all.
    #[default]
    Unset,
    /// A start was requested. Stays `Running` through every refusal (no bank
    /// selected, verify refused, spawn failed) — the request happened, so the
    /// gap between it and reality is exactly what needs reporting.
    Running,
    /// A stop was requested, or the admin gate refused the start.
    Stopped,
}

impl std::fmt::Display for ExpectedState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExpectedState::Unset => write!(f, "unset"),
            ExpectedState::Running => write!(f, "running"),
            ExpectedState::Stopped => write!(f, "stopped"),
        }
    }
}

/// Who asked — the provenance of the current [`ExpectedState`].
///
/// Answers the question no existing field can: *why is this thing up (or down)?*
/// An operator stop, a reboot sweep and an administrative disable all produce
/// `Stopped`, and they call for entirely different responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedBy {
    /// A caller that did not say. The default for `start_vm`, so adding this
    /// axis broke no existing call site.
    #[default]
    Unspecified,
    /// The host's boot-time auto-start sweep.
    Autostart,
    /// `POST /vms/{name}/start` or `/restart` — a manual poke, or component-mgr
    /// relaunching after an OTA bank flip.
    Api,
    /// `POST /vms/{name}/stop`.
    StopApi,
    /// `stop_all_for_reboot` — every guest signalled at once for a node reboot,
    /// which is a very different thing from an operator stopping one VM.
    RebootSweep,
    /// The admin gate refused the start: persisted operator intent, read from
    /// the signed boot selector.
    AdminDisable,
}

impl std::fmt::Display for ExpectedBy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExpectedBy::Unspecified => write!(f, "unspecified"),
            ExpectedBy::Autostart => write!(f, "autostart"),
            ExpectedBy::Api => write!(f, "api"),
            ExpectedBy::StopApi => write!(f, "stop_api"),
            ExpectedBy::RebootSweep => write!(f, "reboot_sweep"),
            ExpectedBy::AdminDisable => write!(f, "admin_disable"),
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
    /// The declared-intent axis: what this VM is *supposed* to be doing. Read
    /// together with `status` — the pair is what makes "healthy" computable.
    pub expected: ExpectedState,
    /// Who asked for `expected`.
    pub expected_by: ExpectedBy,
    /// How long `expected` has held, in milliseconds on the MONOTONIC clock.
    ///
    /// The clock the intent axis needs and `for_ms` cannot supply: `for_ms`
    /// restarts on every OBSERVED transition, so a guest flapping
    /// `starting → failed → starting` resets it and no observer can accumulate
    /// "wrong for N ms". A disagreement begins at `max(expected_since,
    /// status_since)`, so `min(for_ms, expected_for_ms)` is exactly its
    /// duration — computed by the observer, from published facts, with no
    /// threshold anywhere in here.
    pub expected_for_ms: u64,
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
    /// The declared-intent axis. Recorded from decisions, not read from config —
    /// see [`ExpectedState`].
    expected: ExpectedState,
    expected_by: ExpectedBy,
    /// When `expected` last CHANGED VALUE. A second start request while already
    /// expected-running must not restart this clock, or an observer loses the
    /// only measure of how long a disagreement has lasted.
    expected_since: Instant,
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
            // ...and "nothing has been asked" is its own answer on the intent
            // axis, distinct from "asked to stay down".
            expected: ExpectedState::Unset,
            expected_by: ExpectedBy::Unspecified,
            expected_since: Instant::now(),
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
    pub(crate) fn note_stop_requested(&mut self, by: ExpectedBy) {
        self.stop_requested = true;
        self.failed = false;
        self.reason = Some("stop requested".to_string());
        self.expect(ExpectedState::Stopped, by);
    }

    /// A launch succeeded — the observed record starts clean for the new
    /// lifetime. Deliberately does NOT touch the intent axis: a successful
    /// launch is not a new request, and resetting `expected_since` here would
    /// destroy the dwell clock for the state that was just reached.
    pub(crate) fn note_started(&mut self) {
        self.stop_requested = false;
        self.failed = false;
        self.reason = None;
    }

    /// Record the declared intent. The `expected_since` clock restarts only on
    /// a real change of value, so a repeated request (the API's synchronous
    /// pre-note followed by the background `start_vm`, or a poll-driven retry)
    /// does not keep zeroing it.
    pub(crate) fn expect(&mut self, expected: ExpectedState, by: ExpectedBy) {
        if self.expected != expected {
            self.expected = expected;
            self.expected_since = Instant::now();
        }
        self.expected_by = by;
    }

    pub(crate) fn expected(&self) -> ExpectedState {
        self.expected
    }

    pub(crate) fn expected_by(&self) -> ExpectedBy {
        self.expected_by
    }

    /// Monotonic dwell on the intent axis, in milliseconds.
    pub(crate) fn expected_for_ms(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.expected_since)
            .as_millis() as u64
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
        // Same contract for the intent axis: component-mgr parses these as
        // strings too, so a casing slip breaks the wire silently.
        for (s, want) in [
            (ExpectedState::Unset, "unset"),
            (ExpectedState::Running, "running"),
            (ExpectedState::Stopped, "stopped"),
        ] {
            assert_eq!(format!("{s}"), want);
            assert_eq!(serde_json::to_string(&s).unwrap(), format!("\"{want}\""));
        }
        for (s, want) in [
            (ExpectedBy::Unspecified, "unspecified"),
            (ExpectedBy::Autostart, "autostart"),
            (ExpectedBy::Api, "api"),
            (ExpectedBy::StopApi, "stop_api"),
            (ExpectedBy::RebootSweep, "reboot_sweep"),
            (ExpectedBy::AdminDisable, "admin_disable"),
        ] {
            assert_eq!(format!("{s}"), want);
            assert_eq!(serde_json::to_string(&s).unwrap(), format!("\"{want}\""));
        }
    }

    #[test]
    fn expected_defaults_to_unset_not_stopped() {
        // The whole reason for the third value: a node whose external start
        // orchestrator never ran must not read as "stopped, as intended".
        let lc = Lifecycle::default();
        assert_eq!(lc.expected(), ExpectedState::Unset);
        assert_eq!(lc.expected_by(), ExpectedBy::Unspecified);
    }

    #[test]
    fn expected_clock_restarts_only_when_the_intent_changes() {
        let mut lc = Lifecycle::default();
        lc.expect(ExpectedState::Running, ExpectedBy::Api);
        std::thread::sleep(Duration::from_millis(20));

        // Re-stating the same intent (the API's pre-note, then the background
        // start_vm) must not zero the dwell clock...
        let before = lc.expected_for_ms(Instant::now());
        lc.expect(ExpectedState::Running, ExpectedBy::Api);
        assert!(
            lc.expected_for_ms(Instant::now()) >= before,
            "a repeated request must not restart the intent clock"
        );

        // ...but a real change does.
        lc.expect(ExpectedState::Stopped, ExpectedBy::StopApi);
        assert!(lc.expected_for_ms(Instant::now()) < 10);
        assert_eq!(lc.expected_by(), ExpectedBy::StopApi);
    }

    #[test]
    fn note_started_does_not_clear_the_expectation() {
        // note_started resets the OBSERVED record for a fresh lifetime. Touching
        // the intent axis there would both lose the provenance and zero the
        // dwell clock for the state just reached.
        let mut lc = Lifecycle::default();
        lc.expect(ExpectedState::Running, ExpectedBy::Autostart);
        lc.note_started();
        assert_eq!(lc.expected(), ExpectedState::Running);
        assert_eq!(lc.expected_by(), ExpectedBy::Autostart);
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

        lc.note_stop_requested(ExpectedBy::StopApi);
        assert!(!lc.is_failed(), "an operator stop is not a fault");
        assert!(lc.stop_requested());
        assert_eq!(lc.expected(), ExpectedState::Stopped);

        // ...and a successful start clears everything for the new lifetime.
        lc.note_started();
        assert!(!lc.is_failed());
        assert!(!lc.stop_requested());
        assert_eq!(lc.reason(), None);
    }
}
