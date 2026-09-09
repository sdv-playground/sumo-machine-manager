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
