//! Observed component lifecycle — one parsed snapshot of "what is this
//! component's runtime actually doing", from either health source.
//!
//! # Why this exists
//!
//! Four state vocabularies already describe a running component, at four
//! layers: `vm_wire::GuestState` (the heartbeat frame), `vm_mgr::HealthStatus`
//! (vm-service's view of process + heartbeat), `machine_mgr::RuntimeStatus`
//! (the `Component` trait layer), and SOVD's `EntityStatus` (ISO 17978-3
//! ready / notReady). None of them reached an offboard observer with enough
//! resolution to answer the questions an orchestrator actually asks:
//!
//! * *started but not up yet* — `starting` says nothing about **how long**, so
//!   a poller cannot tell a guest 2 s into boot from one wedged for 10 minutes.
//! * *started and failed* — had no representation at all. A guest whose bank
//!   failed to verify reported `stopped`, identical to one an operator stopped
//!   on purpose, so the only way to learn the difference was to wait out the
//!   full timeout and conclude nothing.
//! * *shutting down but not down* — existed inside vm-service and was flattened
//!   before it reached the trait layer.
//!
//! [`GuestLifecycle`] is that snapshot: the coarse status, the **evidence** for
//! it (heartbeat seq, guest state, boot id), and the **clock** (`for_ms`, how
//! long this status has been held). It is derived on every read and never
//! persisted — nothing here survives a reboot, so nothing here can go stale or
//! need a migration.
//!
//! # The clock belongs to the observer
//!
//! Deliberately absent: any threshold. This type reports that a component has
//! been `starting` for 47 s; it does not decide whether that is too long. The
//! deadline lives with the policy — in the orchestrator, whose campaign knows
//! what it is waiting for — because the same 47 s is fine on a cold boot and a
//! failure mid-campaign. Encoding a timeout here would move the policy into
//! the device and freeze it into the wire format.

use machine_mgr::types::{RuntimeState, RuntimeStatus};
use serde_json::{Map, Value};

use crate::backend::GuestHealth;

/// What a component is *supposed* to be doing — the declared-intent axis.
///
/// Redefined here rather than imported from `vm-mgr` for the same reason
/// `status` is kept as a string: this crate must degrade, not error, when a
/// newer source publishes a word it does not know. Parsing lives in
/// [`parse_expected`], and everything it cannot recognise — including the
/// absence of the field and vm-service's own "no intent recorded" — arrives as
/// `None`, which yields no verdict at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedState {
    Running,
    Stopped,
}

impl ExpectedState {
    fn as_str(self) -> &'static str {
        match self {
            ExpectedState::Running => "running",
            ExpectedState::Stopped => "stopped",
        }
    }
}

/// Whether the observation agrees with the declared intent — the verdict that
/// used to be re-guessed by every consumer, computed once, here.
///
/// Three invariants an observer may rely on, and which keep this from growing
/// into a policy engine:
///
/// * **No clock is read.** The verdict is a function of the two state words
///   alone. How long a disagreement has lasted, and how long is too long, stay
///   with the observer — `min(for_ms, expected_for_ms)` is the dwell, and only
///   the caller's campaign knows the deadline.
/// * **`Diverged` is not a prediction.** It says the observation contradicts
///   the recorded intent *right now*, nothing about whether it will resolve:
///   intent `stopped` + observed `running` is self-resolving (a shutdown in
///   flight), while intent `running` + observed `failed` is terminal — because
///   `failed` already is, not because of this verdict.
/// * **It is recomputable.** Every input is published in the same body, so a
///   client can derive the same answer and explain it. Nothing here is a
///   judgement only the device could make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Convergence {
    /// Observation matches intent. Note that this is not the same as *usable*:
    /// a component converged on `stopped` is working as asked and still cannot
    /// serve a request.
    Converged,
    /// On its way — the disagreement is expected to resolve without action.
    Transitioning,
    /// The observation contradicts the intent. Something asked for this
    /// component's state and did not get it.
    Diverged,
}

impl Convergence {
    fn as_str(self) -> &'static str {
        match self {
            Convergence::Converged => "converged",
            Convergence::Transitioning => "transitioning",
            Convergence::Diverged => "diverged",
        }
    }
}

/// Parse the intent word from a health body. Unrecognised values — including
/// vm-service's `null` for "nothing has asked", and any word a newer source
/// invents — degrade to `None`, i.e. no basis for a verdict.
fn parse_expected(json: &Value) -> Option<ExpectedState> {
    match json.get("expected").and_then(|v| v.as_str()) {
        Some("running") => Some(ExpectedState::Running),
        Some("stopped") => Some(ExpectedState::Stopped),
        _ => None,
    }
}

/// The reason string a disabled component reports, shared by both views so they
/// cannot word it differently.
pub const ADMIN_DISABLED_REASON: &str = "administratively disabled";

/// Write the three intent keys, omitting whatever is unknown.
fn insert_expectation(
    runtime: &mut Map<String, Value>,
    expected: Option<ExpectedState>,
    expected_by: Option<&str>,
    expected_for_ms: Option<u64>,
) {
    if let Some(expected) = expected {
        runtime.insert("lifecycle_expected".into(), Value::from(expected.as_str()));
    }
    if let Some(by) = expected_by {
        runtime.insert("lifecycle_expected_by".into(), Value::from(by));
    }
    if let Some(for_ms) = expected_for_ms {
        runtime.insert("lifecycle_expected_for_ms".into(), Value::from(for_ms));
    }
}

/// The `x-runtime` / `RuntimeState::detail` body for an administratively
/// disabled component — the one case with an intent but no observation.
///
/// Both views go through here so they cannot drift, which they already had:
/// `runtime_state_snapshot` hand-built `lifecycle_status: "stopped"` while
/// `read_entity_status` published no `lifecycle_*` at all.
///
/// Deliberately **no** `lifecycle_convergence`: nothing was polled (probing a
/// component that is down by design would only burn the health timeout), so
/// there is no observation to compare the intent against. Claiming `converged`
/// here would assert a check that never happened — exactly the dishonesty the
/// two-axis model exists to remove.
pub fn insert_admin_disabled_fields(runtime: &mut Map<String, Value>) {
    runtime.insert("lifecycle_status".into(), Value::from("stopped"));
    runtime.insert(
        "lifecycle_reason".into(),
        Value::from(ADMIN_DISABLED_REASON),
    );
    insert_expectation(
        runtime,
        Some(ExpectedState::Stopped),
        Some("admin_disable"),
        None,
    );
}

/// A component's observed runtime lifecycle at one instant.
///
/// Mirrors the JSON of vm-service's `GET /vms/{name}/health`. Every field
/// except `status` is optional, because the two health sources and the
/// different lifecycle phases genuinely know different amounts: a stopped VM
/// has no heartbeat, a just-launched one has no guest state yet, and an older
/// vm-service does not send the clock fields at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestLifecycle {
    /// The coarse status, as the wire spells it: `starting`, `running`,
    /// `unhealthy`, `shutting_down`, `stopped`, `failed`, `unknown`.
    /// Kept as a string on purpose — this crate must not fail to parse a
    /// status a newer vm-service invented, and an unknown value maps to
    /// [`RuntimeStatus::Unknown`] rather than an error.
    pub status: String,
    /// Guest-reported state code from the heartbeat frame (0 Booting,
    /// 1 Running, 2 Degraded, 3 ShuttingDown). `None` before the guest has
    /// written a heartbeat, or when the component is down.
    pub guest_state: Option<u32>,
    /// Heartbeat sequence counter — liveness evidence.
    pub hb_seq: Option<u32>,
    /// Per-guest-lifetime nonce; a *changed* value proves a fresh boot.
    pub boot_id: Option<u32>,
    /// How long `status` has been held, in milliseconds, on the reporting
    /// host's MONOTONIC clock. `None` when the source does not report it —
    /// which is not the same as `Some(0)` ("changed just now"), and the
    /// difference matters to an observer deciding whether it can trust a
    /// dwell-time deadline at all.
    pub for_ms: Option<u64>,
    /// Wall-clock instant of the transition (UNIX seconds), for log
    /// correlation. Never for deadlines — see `for_ms`.
    pub since_unix_secs: Option<u64>,
    /// Why the component is in `status`, when the status alone doesn't say:
    /// the verify refusal, the missing kernel, "no active bank selected",
    /// "stop requested", "process exited without a stop request".
    pub reason: Option<String>,
    /// The declared intent. `None` when the source publishes none — an older
    /// vm-service, a probe, or a VM nothing has ever asked to run. **Not** the
    /// same as `Some(Stopped)`: no request is not a request to stay down, and
    /// collapsing the two is what would let a node whose start orchestrator
    /// died report as healthy and settled.
    pub expected: Option<ExpectedState>,
    /// Who asked — `autostart`, `api`, `stop_api`, `reboot_sweep`,
    /// `admin_disable`. Kept as a string for the same forward-compatibility
    /// reason as `status`: provenance is for a human to read, and an unknown
    /// word must pass through rather than be dropped.
    pub expected_by: Option<String>,
    /// How long the intent has held, in milliseconds on the source's MONOTONIC
    /// clock. Not redundant with `for_ms`: that one restarts on every observed
    /// transition, so a flapping guest keeps resetting it. A disagreement starts
    /// at the later of the two transitions, which makes
    /// `min(for_ms, expected_for_ms)` exactly the divergence dwell.
    pub expected_for_ms: Option<u64>,
}

impl GuestLifecycle {
    /// Parse a `/vms/{name}/health` body. Only `status` is required; every
    /// other field is best-effort so that an older vm-service (no clock
    /// fields) and every lifecycle phase (no heartbeat yet) both parse.
    pub fn from_json(json: &Value) -> Result<Self, String> {
        let status = json
            .get("status")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "health response missing status".to_string())?
            .to_string();
        let u32_field = |key: &str| json.get(key).and_then(|v| v.as_u64()).map(|v| v as u32);
        Ok(Self {
            status,
            guest_state: u32_field("guest_state"),
            hb_seq: u32_field("hb_seq"),
            boot_id: u32_field("boot_id"),
            for_ms: json.get("for_ms").and_then(|v| v.as_u64()),
            since_unix_secs: json.get("since_unix_secs").and_then(|v| v.as_u64()),
            reason: json
                .get("reason")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            expected: parse_expected(json),
            expected_by: json
                .get("expected_by")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            expected_for_ms: json.get("expected_for_ms").and_then(|v| v.as_u64()),
        })
    }

    /// Lift a [`HealthProbe`](crate::backend::HealthProbe) snapshot — the
    /// health source for components with no vm-service behind them (RT/M7).
    ///
    /// A probe only ever synthesises a *running* snapshot (it returns `None`
    /// otherwise), and it has no lifecycle clock, so `for_ms` stays `None`
    /// rather than claiming 0.
    pub fn from_probe(health: &GuestHealth) -> Self {
        Self {
            status: health.status.clone(),
            guest_state: Some(health.guest_state),
            hb_seq: Some(health.hb_seq),
            boot_id: Some(health.boot_id),
            for_ms: None,
            since_unix_secs: None,
            reason: None,
            // A probe observes; it does not decide. The only intent this crate
            // holds for a probe-backed component is the negative-polarity
            // `admin_disabled()`, and inferring "enabled ⇒ expected running"
            // from it would smuggle config-derived intent back in — wrong for a
            // node whose M7 is deliberately unflashed.
            expected: None,
            expected_by: None,
            expected_for_ms: None,
        }
    }

    /// The component is not running. `failed` and `stopped` differ only in
    /// whether anyone asked for it — both mean no process.
    ///
    /// Note what is NOT here: `unknown` counts as not-down, preserving the
    /// pre-existing rule that only `stopped` meant not-running. `unknown` is
    /// "the process is up but there's no heartbeat device to ask", so treating
    /// it as down would be a downgrade in honesty, not an upgrade.
    pub fn is_down(&self) -> bool {
        self.status == "stopped" || self.status == "failed"
    }

    /// Terminal: nothing will change without an action. An orchestrator that
    /// sees this should stop waiting and report — the remedy is a re-flash, a
    /// start, or an operator, never more patience.
    pub fn is_failed(&self) -> bool {
        self.status == "failed"
    }

    /// Fully up: the guest is running AND its heartbeat says so. Both halves
    /// are needed — a live process whose guest never reached userspace is not
    /// a component that can answer requests.
    pub fn is_up(&self) -> bool {
        self.status == "running" && self.guest_state == Some(1)
    }

    /// Compare the two axes. `None` whenever a verdict would have no basis —
    /// see [`Convergence`] for the invariants this upholds.
    ///
    /// | intent | observed | verdict |
    /// |---|---|---|
    /// | `running` | up (`running` + guest state 1) | converged |
    /// | `running` | `stopped`, `failed` | **diverged** |
    /// | `running` | `starting`, `shutting_down`, `unhealthy`, `running` not yet up | transitioning |
    /// | `running` | `unknown` | *no verdict* |
    /// | `stopped` | down (`stopped` or `failed`) | converged |
    /// | `stopped` | `starting`, `shutting_down` | transitioning |
    /// | `stopped` | `running`, `unhealthy`, `unknown` | **diverged** |
    /// | absent | anything | *no verdict* |
    ///
    /// `unknown` is asymmetric on purpose. It means "the process is up but there
    /// is no heartbeat device to ask", which is *no evidence* about readiness
    /// under intent `running` (so: omit — `Option` is already this type's word
    /// for "cannot tell") but *positive evidence of contradiction* under intent
    /// `stopped`, where a live process is the whole question. The consequence is
    /// deliberate and visible in the status word itself: a VM configured with no
    /// health device never gets a readiness verdict.
    ///
    /// `failed` under intent `stopped` is converged, not diverged: down is what
    /// was asked for, and how it got there is what `lifecycle_reason` is for.
    pub fn convergence(&self) -> Option<Convergence> {
        let expected = self.expected?;
        let status = self.status.as_str();
        match expected {
            ExpectedState::Running => {
                if self.is_up() {
                    Some(Convergence::Converged)
                } else {
                    match status {
                        "stopped" | "failed" => Some(Convergence::Diverged),
                        // `running` without a healthy guest state lands here:
                        // the process is up and the guest has not arrived yet.
                        "starting" | "shutting_down" | "unhealthy" | "running" => {
                            Some(Convergence::Transitioning)
                        }
                        // `unknown`, and anything a newer source invents: no
                        // evidence, so no verdict.
                        _ => None,
                    }
                }
            }
            ExpectedState::Stopped => match status {
                "stopped" | "failed" => Some(Convergence::Converged),
                "starting" | "shutting_down" => Some(Convergence::Transitioning),
                "running" | "unhealthy" | "unknown" => Some(Convergence::Diverged),
                _ => None,
            },
        }
    }

    /// Map onto the coarse `Component`-trait status. Lossy by design: the
    /// precise status, its clock, and its reason ride in the detail payload
    /// ([`Self::insert_runtime_fields`]) so nothing is lost at this boundary.
    pub fn runtime_status(&self) -> RuntimeStatus {
        match self.status.as_str() {
            "running" => RuntimeStatus::Running,
            "starting" => RuntimeStatus::Booting,
            // Running-but-not-serving: stale heartbeat or a guest reporting
            // Degraded. `Faulted` is the trait layer's only word for it, and
            // it is the right one — the component is not usable.
            "unhealthy" | "failed" => RuntimeStatus::Faulted,
            "shutting_down" => RuntimeStatus::ShuttingDown,
            "stopped" => RuntimeStatus::Stopped,
            _ => RuntimeStatus::Unknown,
        }
    }

    /// The `Component::runtime_state` view: coarse status + every observed
    /// fact as detail.
    pub fn runtime_state(&self) -> RuntimeState {
        let mut detail = Map::new();
        self.insert_runtime_fields(&mut detail);
        RuntimeState {
            status: self.runtime_status(),
            detail: Value::Object(detail),
        }
    }

    /// Write the observation into a `/status` `x-runtime` map (also used as the
    /// `RuntimeState::detail` body, so the two views cannot drift).
    ///
    /// Absent facts are omitted rather than sent as `null`: a reader must be
    /// able to tell "no heartbeat" from "heartbeat seq 0".
    pub fn insert_runtime_fields(&self, runtime: &mut Map<String, Value>) {
        if let Some(hb_seq) = self.hb_seq {
            runtime.insert("hb_seq".into(), Value::from(hb_seq));
        }
        if let Some(boot_id) = self.boot_id {
            runtime.insert("boot_id".into(), Value::from(boot_id));
        }
        if let Some(guest_state) = self.guest_state {
            runtime.insert("guest_state".into(), Value::from(guest_state));
        }
        runtime.insert("lifecycle_status".into(), Value::from(self.status.clone()));
        if let Some(for_ms) = self.for_ms {
            runtime.insert("lifecycle_for_ms".into(), Value::from(for_ms));
        }
        if let Some(since) = self.since_unix_secs {
            runtime.insert("lifecycle_since".into(), Value::from(since));
        }
        if let Some(reason) = &self.reason {
            runtime.insert("lifecycle_reason".into(), Value::from(reason.clone()));
        }
        self.insert_expectation_fields(runtime);
    }

    /// Write the intent axis and the verdict derived from both axes.
    ///
    /// The `lifecycle_` prefix is deliberate: the observed half is uniformly
    /// prefixed, and a bare `expected_state` would sit next to `admin_state`
    /// meaning something entirely different (that one is the persisted operator
    /// decision, this one is what the running system was last asked to do).
    pub fn insert_expectation_fields(&self, runtime: &mut Map<String, Value>) {
        insert_expectation(
            runtime,
            self.expected,
            self.expected_by.as_deref(),
            self.expected_for_ms,
        );
        // Omitted, never `null`, and never invented: no intent (or no evidence)
        // means no verdict, which a reader must be able to tell apart from
        // "checked, and it disagrees".
        if let Some(convergence) = self.convergence() {
            runtime.insert(
                "lifecycle_convergence".into(),
                Value::from(convergence.as_str()),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health(status: &str) -> Value {
        serde_json::json!({"status": status})
    }

    #[test]
    fn a_full_running_body_parses_every_field() {
        let lc = GuestLifecycle::from_json(&serde_json::json!({
            "status": "running",
            "guest_state": 1,
            "hb_seq": 1234,
            "boot_id": 42,
            "for_ms": 9000,
            "since_unix_secs": 1_757_000_000u64,
            "reason": null,
        }))
        .unwrap();

        assert!(lc.is_up());
        assert!(!lc.is_down());
        assert_eq!(lc.for_ms, Some(9000));
        assert_eq!(lc.since_unix_secs, Some(1_757_000_000));
        assert_eq!(lc.reason, None);
        assert_eq!(lc.runtime_status(), RuntimeStatus::Running);
    }

    #[test]
    fn an_older_vm_service_body_still_parses() {
        // No for_ms / since_unix_secs / reason — the pre-step-1 wire shape.
        // `for_ms` must stay None, NOT 0: an observer has to be able to tell
        // "this host doesn't report dwell time" from "it just changed".
        let lc = GuestLifecycle::from_json(&serde_json::json!({
            "status": "running", "guest_state": 1, "hb_seq": 7, "boot_id": 3,
        }))
        .unwrap();
        assert!(lc.is_up());
        assert_eq!(lc.for_ms, None);
        assert_eq!(lc.since_unix_secs, None);
    }

    #[test]
    fn a_status_only_body_parses_and_the_missing_evidence_is_absent() {
        let lc = GuestLifecycle::from_json(&health("starting")).unwrap();
        assert_eq!(lc.runtime_status(), RuntimeStatus::Booting);
        assert!(!lc.is_up(), "starting is not up");
        assert!(!lc.is_down(), "starting is not down either");
        assert_eq!(lc.hb_seq, None);

        let mut runtime = Map::new();
        lc.insert_runtime_fields(&mut runtime);
        assert_eq!(runtime.get("lifecycle_status").unwrap(), "starting");
        assert!(
            !runtime.contains_key("hb_seq"),
            "absent evidence must be OMITTED, not null — a reader has to tell \
             'no heartbeat' from 'seq 0'"
        );
    }

    #[test]
    fn a_body_without_status_is_an_error() {
        assert!(GuestLifecycle::from_json(&serde_json::json!({"hb_seq": 1})).is_err());
    }

    #[test]
    fn failed_is_down_terminal_and_faulted() {
        let lc = GuestLifecycle::from_json(&serde_json::json!({
            "status": "failed",
            "reason": "pre-launch verify failed: bad signature",
            "for_ms": 1500,
        }))
        .unwrap();

        assert!(lc.is_down());
        assert!(lc.is_failed());
        assert!(!lc.is_up());
        assert_eq!(lc.runtime_status(), RuntimeStatus::Faulted);

        let mut runtime = Map::new();
        lc.insert_runtime_fields(&mut runtime);
        assert_eq!(
            runtime.get("lifecycle_reason").unwrap(),
            "pre-launch verify failed: bad signature",
            "the reason is the whole point of the state"
        );
    }

    #[test]
    fn stopped_is_down_but_not_a_fault() {
        let lc = GuestLifecycle::from_json(&health("stopped")).unwrap();
        assert!(lc.is_down());
        assert!(!lc.is_failed());
        assert_eq!(lc.runtime_status(), RuntimeStatus::Stopped);
    }

    #[test]
    fn shutting_down_is_neither_up_nor_down() {
        // The gap that used to be flattened: the process is still alive, so
        // reporting Stopped would be wrong, and it is not a fault either.
        let lc = GuestLifecycle::from_json(&health("shutting_down")).unwrap();
        assert!(!lc.is_up());
        assert!(!lc.is_down());
        assert!(!lc.is_failed());
        assert_eq!(lc.runtime_status(), RuntimeStatus::ShuttingDown);
    }

    #[test]
    fn unhealthy_is_running_but_faulted() {
        let lc = GuestLifecycle::from_json(&health("unhealthy")).unwrap();
        assert!(!lc.is_down(), "the process is still up");
        assert!(!lc.is_up());
        assert_eq!(lc.runtime_status(), RuntimeStatus::Faulted);
    }

    #[test]
    fn an_unrecognised_status_maps_to_unknown_and_never_errors() {
        // Forward compatibility: a newer vm-service inventing a status must not
        // make an older host fail to read health at all.
        let lc = GuestLifecycle::from_json(&health("hibernating")).unwrap();
        assert_eq!(lc.runtime_status(), RuntimeStatus::Unknown);
        assert!(!lc.is_down());
    }

    #[test]
    fn running_without_a_healthy_guest_state_is_not_up() {
        // status says the process is fine; the guest says it is Degraded.
        let lc = GuestLifecycle::from_json(&serde_json::json!({
            "status": "running", "guest_state": 2, "hb_seq": 5, "boot_id": 1,
        }))
        .unwrap();
        assert!(!lc.is_up(), "both halves must agree");
    }

    #[test]
    fn a_probe_snapshot_carries_no_lifecycle_clock() {
        let lc = GuestLifecycle::from_probe(&GuestHealth {
            guest_state: 1,
            hb_seq: 11,
            boot_id: 22,
            status: "running".into(),
        });
        assert!(lc.is_up());
        assert_eq!(lc.for_ms, None, "a probe has no dwell clock — don't invent 0");
        assert_eq!(lc.runtime_status(), RuntimeStatus::Running);
    }

    /// Recompute the verdict from a published body, using only the keys a
    /// remote client can see. Invariant (c) on [`Convergence`]: no input to the
    /// verdict is private to the device.
    fn recompute(runtime: &Map<String, Value>) -> Option<Convergence> {
        let expected = runtime.get("lifecycle_expected")?.as_str()?;
        let status = runtime.get("lifecycle_status")?.as_str()?;
        let up =
            status == "running" && runtime.get("guest_state").and_then(Value::as_u64) == Some(1);
        match expected {
            "running" if up => Some(Convergence::Converged),
            "running" => match status {
                "stopped" | "failed" => Some(Convergence::Diverged),
                "starting" | "shutting_down" | "unhealthy" | "running" => {
                    Some(Convergence::Transitioning)
                }
                _ => None,
            },
            "stopped" => match status {
                "stopped" | "failed" => Some(Convergence::Converged),
                "starting" | "shutting_down" => Some(Convergence::Transitioning),
                "running" | "unhealthy" | "unknown" => Some(Convergence::Diverged),
                _ => None,
            },
            _ => None,
        }
    }

    #[test]
    fn convergence_table_covers_every_status_under_both_intents() {
        use Convergence::*;
        // Every observed status against both intents, including the omissions.
        // This table IS the contract — the reason the device publishes a verdict
        // at all is that each consumer was deriving a different one of these.
        let cases: &[(&str, &str, Option<u32>, Option<Convergence>)] = &[
            // Asked to run.
            ("running", "running", Some(1), Some(Converged)),
            // Process up, guest not there yet (or degraded): on its way, and NOT
            // converged — "the process exists" was never the question.
            ("running", "running", Some(2), Some(Transitioning)),
            ("running", "running", None, Some(Transitioning)),
            ("running", "starting", None, Some(Transitioning)),
            ("running", "unhealthy", None, Some(Transitioning)),
            ("running", "shutting_down", None, Some(Transitioning)),
            // The two that used to be indistinguishable from a deliberate stop.
            ("running", "stopped", None, Some(Diverged)),
            ("running", "failed", None, Some(Diverged)),
            // `unknown` = no heartbeat device to ask. No evidence about
            // readiness ⇒ no verdict, rather than a guess in either direction.
            ("running", "unknown", None, None),
            ("running", "hibernating", None, None),
            // Asked to stay down.
            ("stopped", "stopped", None, Some(Converged)),
            // `failed` under intent `stopped` is converged: down is what was
            // asked for. HOW it got down is what `lifecycle_reason` carries.
            ("stopped", "failed", None, Some(Converged)),
            ("stopped", "shutting_down", None, Some(Transitioning)),
            ("stopped", "starting", None, Some(Transitioning)),
            // A live process is exactly the contradiction here — which is why
            // `unknown` diverges under this intent while omitting under the
            // other one.
            ("stopped", "running", Some(1), Some(Diverged)),
            ("stopped", "unhealthy", None, Some(Diverged)),
            ("stopped", "unknown", None, Some(Diverged)),
            ("stopped", "hibernating", None, None),
        ];

        for (expected, status, guest_state, want) in cases {
            let mut body = serde_json::json!({"status": status, "expected": expected});
            if let Some(gs) = guest_state {
                body["guest_state"] = Value::from(*gs);
            }
            let lc = GuestLifecycle::from_json(&body).unwrap();
            assert_eq!(
                lc.convergence(),
                *want,
                "expected={expected} status={status} guest_state={guest_state:?}"
            );

            // And the same verdict falls out of the published body alone.
            let mut runtime = Map::new();
            lc.insert_runtime_fields(&mut runtime);
            assert_eq!(
                recompute(&runtime),
                *want,
                "a client must reach the same verdict from the body: {runtime:?}"
            );
        }
    }

    #[test]
    fn convergence_is_absent_when_the_source_publishes_no_expectation() {
        // Three shapes of "no intent", all of which must yield no verdict:
        // an older vm-service (no key), an explicit null, and a word this
        // version does not know.
        for body in [
            serde_json::json!({"status": "stopped"}),
            serde_json::json!({"status": "stopped", "expected": null}),
            serde_json::json!({"status": "stopped", "expected": "quiesced"}),
        ] {
            let lc = GuestLifecycle::from_json(&body).unwrap();
            assert_eq!(lc.expected, None);
            assert_eq!(
                lc.convergence(),
                None,
                "no intent is NOT 'expected stopped' — a stopped component whose \
                 starter never ran must not read as converged: {body}"
            );

            let mut runtime = Map::new();
            lc.insert_runtime_fields(&mut runtime);
            assert!(!runtime.contains_key("lifecycle_expected"));
            assert!(
                !runtime.contains_key("lifecycle_convergence"),
                "an absent verdict is omitted, never null"
            );
        }
    }

    #[test]
    fn an_intent_body_publishes_its_provenance_and_its_own_clock() {
        let lc = GuestLifecycle::from_json(&serde_json::json!({
            "status": "stopped",
            "reason": "no active bank selected",
            "for_ms": 90_000,
            "expected": "running",
            "expected_by": "autostart",
            "expected_for_ms": 30_000,
        }))
        .unwrap();

        assert_eq!(lc.convergence(), Some(Convergence::Diverged));
        let mut runtime = Map::new();
        lc.insert_runtime_fields(&mut runtime);
        assert_eq!(runtime["lifecycle_convergence"], "diverged");
        assert_eq!(runtime["lifecycle_expected"], "running");
        assert_eq!(runtime["lifecycle_expected_by"], "autostart");
        // Both clocks ride along so the observer can take the shorter one: the
        // component has been down for 90 s but only WRONGLY down for 30 s.
        assert_eq!(runtime["lifecycle_for_ms"], 90_000);
        assert_eq!(runtime["lifecycle_expected_for_ms"], 30_000);
        assert_eq!(
            lc.for_ms.unwrap().min(lc.expected_for_ms.unwrap()),
            30_000,
            "the divergence is bounded by the younger of the two transitions"
        );
    }

    #[test]
    fn an_unobservable_guest_gets_no_readiness_verdict_but_a_stopped_intent_diverges() {
        // `unknown`: the process is up, no heartbeat device to ask. Under intent
        // `running` that is no evidence at all; under intent `stopped` the live
        // process IS the contradiction. The cost of the asymmetry is explicit —
        // a VM with no health device never gets a readiness verdict — and the
        // status word says why.
        let running = GuestLifecycle::from_json(
            &serde_json::json!({"status": "unknown", "expected": "running"}),
        )
        .unwrap();
        assert_eq!(running.convergence(), None);

        let stopped = GuestLifecycle::from_json(
            &serde_json::json!({"status": "unknown", "expected": "stopped"}),
        )
        .unwrap();
        assert_eq!(stopped.convergence(), Some(Convergence::Diverged));
    }

    #[test]
    fn a_probe_snapshot_has_no_intent() {
        // The only intent this crate holds for a probe-backed component is the
        // negative `admin_disabled()`. Turning "not disabled" into "expected
        // running" would be config-derived intent by the back door, and wrong
        // for a node whose M7 is deliberately unflashed.
        let lc = GuestLifecycle::from_probe(&GuestHealth {
            guest_state: 1,
            hb_seq: 11,
            boot_id: 22,
            status: "running".into(),
        });
        assert_eq!(lc.expected, None);
        assert_eq!(lc.convergence(), None);
    }

    #[test]
    fn the_disabled_body_states_an_intent_and_claims_no_observation() {
        let mut runtime = Map::new();
        insert_admin_disabled_fields(&mut runtime);

        assert_eq!(runtime["lifecycle_status"], "stopped");
        assert_eq!(runtime["lifecycle_reason"], ADMIN_DISABLED_REASON);
        assert_eq!(runtime["lifecycle_expected"], "stopped");
        assert_eq!(runtime["lifecycle_expected_by"], "admin_disable");
        assert!(
            !runtime.contains_key("lifecycle_convergence"),
            "nothing was polled, so there is no observation to compare against — \
             'converged' would assert a check that never happened"
        );
        assert!(
            !runtime.contains_key("lifecycle_expected_for_ms"),
            "the disable is persisted, not clocked by this process"
        );
    }

    #[test]
    fn runtime_state_detail_and_x_runtime_are_the_same_body() {
        // One writer for both views, so /status and the trait layer cannot
        // disagree about what the device observed.
        let lc = GuestLifecycle::from_json(&serde_json::json!({
            "status": "starting", "for_ms": 4200,
        }))
        .unwrap();

        let state = lc.runtime_state();
        assert_eq!(state.status, RuntimeStatus::Booting);

        let mut expected = Map::new();
        lc.insert_runtime_fields(&mut expected);
        assert_eq!(state.detail, Value::Object(expected));
        assert_eq!(state.detail["lifecycle_for_ms"], 4200);
    }
}
