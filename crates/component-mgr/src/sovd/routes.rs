//! Reusable SOVD route fragments served by any sumo-stack deployment
//! that exposes a `Machine`.
//!
//! These vendor extensions live in sumo-mm (not SOVDd) per the
//! three-layer rule in `tasks/iso-17978-compliance.md` §1 — SOVDd stays
//! ISO 17978-3 spec-pure and replaceable.  Binaries (the `vm-sovd` bin
//! shipped here, plus closed-source production variants) merge these
//! routes into their own router
//! to expose the same wire.

use std::sync::{Arc, Mutex};

use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use machine_mgr::node_update::{Durable, NodeCoordinator, NodePhase, NodeUpdateState};
use machine_mgr::{Component, FlashId, FlashState, Machine, MachineError};
use nv_store::block::BlockDevice;
use nv_store::store::NvStore;
use nv_store::types::NUM_BANK_SETS;
use sovd_core::{OperationExecution, OperationStatus};

/// `GET /vehicle/v1/data/x-sumo-update-state` — the node's update-transaction
/// state (phase + the components involved), for the orchestrator to poll before
/// each campaign step and refuse to proceed while a prior transaction is
/// unresolved. Derived from the shared NV reboot-owed record (`NvUpdateSession`)
/// and per-bank `committed`, plus the coordinator's in-memory staging. An `x-sumo`
/// vendor route (sumo-mm, not SOVDd); see `docs/design/node-update-state.md`.
pub fn update_state_router<D: BlockDevice + Send + 'static>(
    nv: Arc<Mutex<NvStore<D>>>,
    coord: Arc<NodeCoordinator>,
) -> Router {
    Router::new().route(
        "/vehicle/v1/data/x-sumo-update-state",
        get(move || {
            let nv = nv.clone();
            let coord = coord.clone();
            async move { update_state(nv, coord).await }
        }),
    )
}

/// The `x-sumo-update-state` resource body — the node's update-transaction
/// phase plus the component ids the transaction covers.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct UpdateStateResponse {
    pub phase: String,
    pub components: Vec<String>,
}

/// `GET /vehicle/v1/data/x-sumo-update-state` — the handler behind
/// [`update_state_router`].
#[utoipa::path(
    get,
    path = "/vehicle/v1/data/x-sumo-update-state",
    tag = "x-sumo-vendor-extension",
    responses(
        (status = 200, description = "The node's update-transaction phase and the components it covers.", body = UpdateStateResponse),
    ),
)]
pub(crate) async fn update_state<D: BlockDevice>(
    nv: Arc<Mutex<NvStore<D>>>,
    coord: Arc<NodeCoordinator>,
) -> Json<UpdateStateResponse> {
    let st = derive_node_update_state(&nv, &coord);
    Json(UpdateStateResponse {
        phase: st.phase.as_str().to_string(),
        components: st.components,
    })
}

/// Derive the node's update-transaction state from NV + the coordinator's
/// in-memory staging — the shared derivation behind both the
/// `x-sumo-update-state` resource and the commit gate ([`handle_verdict`]).
/// Translates the durable reboot-owed bitmask and per-bank `committed` flags
/// into component labels, then folds in the coordinator's staging.
fn derive_node_update_state<D: BlockDevice>(
    nv: &Mutex<NvStore<D>>,
    coord: &NodeCoordinator,
) -> NodeUpdateState {
    let (durable, in_trial) = {
        let nv = nv.lock().expect("nv lock poisoned");
        let session = nv.read_update_session().unwrap_or_default();
        let reboot_owed: Vec<String> = (0..NUM_BANK_SETS)
            .filter(|&i| session.reboot_owed & (1u16 << i) != 0)
            .map(|i| coord.label(i))
            .collect();
        let in_trial: Vec<String> = nv
            .read_boot_state()
            .map(|s| {
                (0..NUM_BANK_SETS)
                    .filter(|&i| !s.banks[i].committed)
                    .map(|i| coord.label(i))
                    .collect()
            })
            .unwrap_or_default();
        (
            Durable {
                session_id: session.session_id,
                reboot_owed,
            },
            in_trial,
        )
    };
    coord.node_update_state(&durable, &in_trial)
}

/// Build the HSM component's SOVD vendor surface — the key-slot data resource
/// and the CSR operation.
///
/// Wire:
///
///   `GET  /vehicle/v1/components/hsm/data/keys`
///        → 200 JSON `{ "provisioned": bool, "items": [ { id, kind,
///          has_certificate, allowed_ops, public_key_der_base64 } ] }` — ALWAYS
///          served (device-generated keys exist from first boot); `provisioned`
///          is the device's own state, so callers read it instead of inferring
///          from a status code. Every slot is listed — key slots (`kind` =
///          `EC-P256`/`AES-256`/…) AND the monotonic counter (`kind` =
///          `monotonic`). Public-only; `public_key_der_base64` is the SPKI for
///          asymmetric key slots, `null` for symmetric keys and the counter.
///   `POST /vehicle/v1/components/hsm/operations/x-sumo-csr/executions`
///        body `{ "key_id": "<slot>" }` → 200 ISO 17978-3 §7.14 operation
///        execution; `result.csr_der_base64` is the PKCS#10 CSR.
///
/// `data/keys` is a SOVD **data** resource and returns only non-compromising
/// metadata — never key material (the keystore manifest holds no private bytes).
/// Generating a CSR **signs** (proof-of-possession), so it's an **operation**,
/// not a data read — a `POST …/operations/x-sumo-csr/executions` keyed on the
/// slot, addressing any device-generated key (`tls-identity`, `device-decrypt`,
/// …). Both are `x-sumo` vendor extensions (neither is SOVD-native) and live in
/// sumo-mm, not SOVDd, per the three-layer rule. The signed cert comes back via
/// the SUIT keystore update (one channel — `feedback_hsm_one_channel_key_material.md`).
///
/// NOTE: this is machine-level SOVD surface served from the `component-mgr`
/// crate — it spans all components, not just VMs (hence the rename from the
/// old `vm-mgr` name).
pub fn hsm_router(machine: Arc<dyn Machine>) -> Router {
    let csr = machine.clone();
    Router::new()
        .route(
            "/vehicle/v1/components/hsm/data/keys",
            get(move || {
                let machine = machine.clone();
                async move { hsm_keys_list(machine).await }
            }),
        )
        .route(
            "/vehicle/v1/components/hsm/operations/x-sumo-csr/executions",
            post(move |Json(req): Json<CsrRequest>| {
                let machine = csr.clone();
                async move { hsm_csr_execute(machine, req).await }
            }),
        )
}

/// One HSM key-slot entry in the [`HsmKeysResponse`] inventory — public
/// metadata only, never key material.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct HsmKeyEntry {
    pub id: String,
    pub kind: String,
    pub has_certificate: bool,
    pub allowed_ops: Option<Vec<String>>,
    pub public_key_der_base64: Option<String>,
}

/// The `hsm/data/keys` inventory: the device's provisioning state plus every
/// key slot.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct HsmKeysResponse {
    pub provisioned: bool,
    pub items: Vec<HsmKeyEntry>,
}

/// `GET …/hsm/data/keys` — the key-slot inventory (public metadata only).
#[utoipa::path(
    get,
    path = "/vehicle/v1/components/hsm/data/keys",
    tag = "x-sumo-vendor-extension",
    responses(
        (status = 200, description = "The HSM key-slot inventory (public metadata only; never key material).", body = HsmKeysResponse),
        (status = 503, description = "No HSM component, or the HSM keys are unavailable.", body = String),
    ),
)]
pub(crate) async fn hsm_keys_list(machine: Arc<dyn Machine>) -> axum::response::Response {
    let Some(comp) = machine.component("hsm") else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "no hsm component".to_string(),
        )
            .into_response();
    };
    match comp.list_keys().await {
        Ok(inv) => {
            let items: Vec<HsmKeyEntry> = inv
                .keys
                .into_iter()
                .map(|k| {
                    use base64::Engine;
                    let public_key_der_base64 = k
                        .public_key
                        .as_ref()
                        .map(|der| base64::engine::general_purpose::STANDARD.encode(der));
                    HsmKeyEntry {
                        id: k.key_id,
                        kind: k.kind.label().to_string(),
                        has_certificate: k.has_certificate,
                        allowed_ops: k.allowed_ops,
                        public_key_der_base64,
                    }
                })
                .collect();
            Json(HsmKeysResponse {
                provisioned: inv.provisioned,
                items,
            })
            .into_response()
        }
        Err(MachineError::NotSupported(_)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "HSM keys unavailable".to_string(),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "list keys failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("list keys error: {e}"),
            )
                .into_response()
        }
    }
}

/// Body of the `x-sumo-csr` operation: which key slot to generate a CSR for.
#[derive(serde::Deserialize, utoipa::ToSchema)]
pub(crate) struct CsrRequest {
    key_id: String,
}

/// The `result` of a successful `x-sumo-csr` execution: the requested slot and
/// its PKCS#10 CSR (DER, base64).
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct CsrResult {
    pub key_id: String,
    pub csr_der_base64: String,
}

/// `POST …/hsm/operations/x-sumo-csr/executions` — sign a PKCS#10 CSR for the
/// requested slot and return it (DER, base64) in an operation execution.
#[utoipa::path(
    post,
    path = "/vehicle/v1/components/hsm/operations/x-sumo-csr/executions",
    tag = "x-sumo-vendor-extension",
    request_body = CsrRequest,
    responses(
        (status = 200, description = "CSR generated; returned in an ISO 17978-3 §7.14 operation execution whose `result` is a CsrResult.", body = super::openapi::doc::OperationExecution),
        (status = 403, description = "Policy rejected CSR generation for this slot (failed execution).", body = super::openapi::doc::OperationExecution),
        (status = 503, description = "No HSM component, or CSR not configured.", body = String),
    ),
)]
pub(crate) async fn hsm_csr_execute(
    machine: Arc<dyn Machine>,
    req: CsrRequest,
) -> axum::response::Response {
    const OP_ID: &str = "x-sumo-csr";
    let Some(comp) = machine.component("hsm") else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "no hsm component".to_string(),
        )
            .into_response();
    };
    let now = chrono::Utc::now();
    match comp.get_csr(&req.key_id).await {
        Ok(csr) => {
            use base64::Engine;
            let der_b64 = base64::engine::general_purpose::STANDARD.encode(csr.as_bytes());
            tracing::info!(key = %req.key_id, "CSR generated ({} bytes)", csr.as_bytes().len());
            let body = OperationExecution {
                execution_id: OP_ID.to_string(),
                operation_id: OP_ID.to_string(),
                status: OperationStatus::Completed,
                result: Some(
                    serde_json::to_value(CsrResult {
                        key_id: req.key_id,
                        csr_der_base64: der_b64,
                    })
                    .expect("CsrResult is infallibly serializable"),
                ),
                error: None,
                started_at: now,
                completed_at: Some(now),
            };
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => {
            let (code, msg) = match &e {
                MachineError::PolicyRejected(s) => (StatusCode::FORBIDDEN, s.clone()),
                MachineError::NotSupported(_) => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CSR not configured".to_string(),
                ),
                other => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("CSR error: {other}"),
                ),
            };
            tracing::warn!(key = %req.key_id, error = %e, "CSR operation failed");
            let body = OperationExecution {
                execution_id: OP_ID.to_string(),
                operation_id: OP_ID.to_string(),
                status: OperationStatus::Failed,
                result: None,
                error: Some(msg),
                started_at: now,
                completed_at: Some(now),
            };
            (code, Json(body)).into_response()
        }
    }
}

/// Build the `x-sumo-id` route.
///
/// `GET /vehicle/v1/components/hsm/x-sumo-id` → 200, body = the ECU's id (its
/// HSM device-key thumbprint, lowercase hex) — the token `aud`. Unlike the CSR
/// this is read-only identity, served whether or not the device is provisioned.
/// Vendor extension per ISO 17978-3 §5.3.6.
pub fn device_id_router(machine: Arc<dyn Machine>) -> Router {
    Router::new().route(
        "/vehicle/v1/components/hsm/x-sumo-id",
        get(move || {
            let machine = machine.clone();
            async move {
                let Some(comp) = machine.component("hsm") else {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "no hsm component".to_string(),
                    )
                        .into_response();
                };
                match comp.get_device_id().await {
                    Ok(Some(id)) => ([(header::CONTENT_TYPE, "text/plain")], id).into_response(),
                    Ok(None) => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "device id unavailable".to_string(),
                    )
                        .into_response(),
                    Err(e) => {
                        tracing::error!(error = %e, "device id read failed");
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("device id error: {e}"),
                        )
                            .into_response()
                    }
                }
            }
        }),
    )
}

/// Which way a node-level verdict resolves the node's in-trial components.
#[derive(Clone, Copy)]
enum Verdict {
    Commit,
    Rollback,
}

impl Verdict {
    /// Vendor operation id (also the synthetic execution id — the op is
    /// synchronous, so there is no execution resource to GET).
    fn op_id(self) -> &'static str {
        match self {
            Verdict::Commit => "x-sumo-commit-trials",
            Verdict::Rollback => "x-sumo-rollback-trials",
        }
    }

    /// Result key under which the acted-on component ids are reported.
    fn acted_key(self) -> &'static str {
        match self {
            Verdict::Commit => "committed",
            Verdict::Rollback => "rolled_back",
        }
    }
}

/// Optional POST body for the node-verdict operations. The client MAY supply a
/// `nonce` for replay-proofing — it is echoed verbatim in the execution record,
/// so a caller can tell its own fresh POST from a transport-level replay of an
/// earlier one. An absent body / non-JSON content type deserialises to `None`
/// (old clients, unchanged wire).
#[derive(serde::Deserialize, utoipa::ToSchema)]
pub(crate) struct VerdictRequest {
    #[serde(default)]
    nonce: Option<String>,
}

/// A verdict operation execution with the optional client `nonce` echoed back.
/// `#[serde(flatten)]` keeps the bare [`OperationExecution`] shape for old
/// clients (no nonce ⇒ the field is skipped); a supplied nonce is appended
/// verbatim as a top-level field.
#[derive(serde::Serialize)]
struct VerdictExecution {
    #[serde(flatten)]
    execution: OperationExecution,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
}

/// Outcome of fanning a verdict out across a node's components.
struct VerdictOutcome {
    /// Components the verdict acted on (committed / rolled back).
    acted: Vec<String>,
    /// Components skipped — no activation concept, singleshot, or already
    /// committed. Reported for visibility, not an error.
    skipped: Vec<String>,
    /// Per-component failures, `"{id}: {err}"`.
    errors: Vec<String>,
}

/// Fan a commit/rollback verdict out across a node's components.
///
/// A component is part of the node's update *session* iff it is currently in
/// trial — `supports_rollback && state == Activated`. That predicate is
/// derived from NV (`activation_state` reports `Activated` for an uncommitted
/// banked component even after the node reboot that wiped the in-memory
/// `/updates` sessions), so the set is identical before and after the reboot —
/// which is why a post-reboot verdict needs no per-component session to
/// re-attach. Singleshot / HSM components report `supports_rollback == false`
/// (or no activation state) and are skipped. Idempotent: an already-committed
/// component is no longer `Activated`, so a re-issued verdict skips it.
async fn run_verdict(components: &[Arc<dyn Component>], verdict: Verdict) -> VerdictOutcome {
    let mut out = VerdictOutcome {
        acted: Vec::new(),
        skipped: Vec::new(),
        errors: Vec::new(),
    };
    for comp in components {
        let st = match comp.activation_state().await {
            Ok(Some(st)) => st,
            Ok(None) => {
                out.skipped.push(comp.id().to_string());
                continue;
            }
            Err(e) => {
                out.errors
                    .push(format!("{}: activation_state: {e}", comp.id()));
                continue;
            }
        };
        if !(st.supports_rollback && st.state == FlashState::Activated) {
            out.skipped.push(comp.id().to_string());
            continue;
        }
        // commit/rollback act on the active bank from NV; the per-component
        // session id is gone after the reboot, so the FlashId is advisory.
        let id = FlashId::new("");
        let res = match verdict {
            Verdict::Commit => comp.commit_install(&id).await,
            Verdict::Rollback => comp.rollback_install(&id).await,
        };
        match res {
            Ok(()) => out.acted.push(comp.id().to_string()),
            Err(e) => out.errors.push(format!("{}: {e}", comp.id())),
        }
    }
    out
}

/// Render a [`VerdictOutcome`] as an ISO 17978-3 §7.14 operation execution.
/// `execution_id` is freshly minted per POST (never the op id) and `nonce` is
/// the client's echoed replay token.
fn verdict_response(
    verdict: Verdict,
    execution_id: String,
    nonce: Option<String>,
    out: VerdictOutcome,
) -> axum::response::Response {
    let failed = !out.errors.is_empty();
    let mut result = serde_json::Map::new();
    result.insert(
        verdict.acted_key().to_string(),
        serde_json::json!(out.acted),
    );
    result.insert("skipped".to_string(), serde_json::json!(out.skipped));
    let now = chrono::Utc::now();
    let execution = OperationExecution {
        execution_id,
        operation_id: verdict.op_id().to_string(),
        status: if failed {
            OperationStatus::Failed
        } else {
            OperationStatus::Completed
        },
        result: Some(serde_json::Value::Object(result)),
        error: failed.then(|| out.errors.join("; ")),
        started_at: now,
        completed_at: Some(now),
    };
    let code = if failed {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::OK
    };
    (code, Json(VerdictExecution { execution, nonce })).into_response()
}

/// The commit gate's refusal (HTTP 409): a commit was issued while the node
/// still owes its activation reboot — the armed bank is not the running bank
/// yet, and a trial that fell back to the recovery bank must not be committed
/// (field-proven). Rendered as a failed execution so clients read the reason
/// from the same shape as a normal verdict, with the `nonce` echoed.
fn commit_reboot_pending(execution_id: String, nonce: Option<String>) -> axum::response::Response {
    let now = chrono::Utc::now();
    let execution = OperationExecution {
        execution_id,
        operation_id: Verdict::Commit.op_id().to_string(),
        status: OperationStatus::Failed,
        result: None,
        error: Some(
            "commit refused: a reboot is pending (armed bank not booted) — reset the ECU and let \
             the trial run"
                .to_string(),
        ),
        started_at: now,
        completed_at: Some(now),
    };
    (
        StatusCode::CONFLICT,
        Json(VerdictExecution { execution, nonce }),
    )
        .into_response()
}

async fn handle_verdict<D: BlockDevice>(
    machine: Arc<dyn Machine>,
    nv: Arc<Mutex<NvStore<D>>>,
    coord: Arc<NodeCoordinator>,
    verdict: Verdict,
    req: Option<VerdictRequest>,
) -> axum::response::Response {
    let nonce = req.and_then(|r| r.nonce);
    let execution_id = uuid::Uuid::new_v4().to_string();

    // Commit gate: refuse while the node still owes its activation reboot. In
    // that phase the armed bank has not been booted (a trial boot can fall back
    // to the recovery bank — selector/armed state ≠ running), so committing
    // would lock in a bank the node never ran. `RebootPending` is derived from
    // NV exactly like the `x-sumo-update-state` wire, and is always reachable.
    // Rollback is the recovery path and is never gated here.
    if let Verdict::Commit = verdict {
        if derive_node_update_state(&nv, &coord).phase == NodePhase::RebootPending {
            return commit_reboot_pending(execution_id, nonce);
        }
    }

    let out = run_verdict(machine.components(), verdict).await;
    let acted = out.acted.len();
    let skipped = out.skipped.len();
    let errors = out.errors.len();
    tracing::info!(
        op = verdict.op_id(),
        acted,
        skipped,
        errors,
        "node-level verdict fanned out across the registry"
    );
    verdict_response(verdict, execution_id, nonce, out)
}

/// Build the node-level commit/rollback verdict routes.
///
/// Wire (ISO 17978-3 §7.14 operation executions, at the **entity root**):
///
///   `POST /vehicle/v1/operations/x-sumo-commit-trials/executions`
///   `POST /vehicle/v1/operations/x-sumo-rollback-trials/executions`
///
/// The orchestrator issues ONE verdict per node per campaign step — the update
/// *session* is the commit unit, never a single component. Entity-root
/// addressing (no `{id}` segment) keeps these clear of the dynamic
/// `/components/{id}/operations/{op_id}/...` routes (mirrors the entity-root
/// `factory-reset` op) and means there is no per-component `/updates` session
/// to re-attach after the node reboot — membership is the NV-derived in-trial
/// set, identical before and after the reboot. Vendor extensions live here in
/// sumo-mm, not SOVDd (the three-layer rule, like `csr_router`).
/// `POST /vehicle/v1/operations/x-sumo-commit-trials/executions` — the node
/// commit verdict; see [`node_verdict_router`] for the wire contract.
#[utoipa::path(
    post,
    path = "/vehicle/v1/operations/x-sumo-commit-trials/executions",
    tag = "x-sumo-vendor-extension",
    request_body(content = VerdictRequest, description = "Optional replay nonce; an absent or non-JSON body means no nonce (old-client shape)."),
    responses(
        (status = 200, description = "Verdict applied across the node's in-trial components (`result.committed` / `skipped`).", body = super::openapi::doc::VerdictExecution),
        (status = 409, description = "Refused: a node activation reboot is still owed (armed bank not booted).", body = super::openapi::doc::VerdictExecution),
        (status = 500, description = "One or more components failed to commit (failed execution).", body = super::openapi::doc::VerdictExecution),
    ),
)]
pub(crate) async fn commit_trials<D: BlockDevice>(
    machine: Arc<dyn Machine>,
    nv: Arc<Mutex<NvStore<D>>>,
    coord: Arc<NodeCoordinator>,
    req: Option<VerdictRequest>,
) -> axum::response::Response {
    handle_verdict(machine, nv, coord, Verdict::Commit, req).await
}

/// `POST /vehicle/v1/operations/x-sumo-rollback-trials/executions` — the node
/// rollback verdict; see [`node_verdict_router`] for the wire contract.
#[utoipa::path(
    post,
    path = "/vehicle/v1/operations/x-sumo-rollback-trials/executions",
    tag = "x-sumo-vendor-extension",
    request_body(content = VerdictRequest, description = "Optional replay nonce; an absent or non-JSON body means no nonce (old-client shape)."),
    responses(
        (status = 200, description = "Verdict applied across the node's in-trial components (`result.rolled_back` / `skipped`).", body = super::openapi::doc::VerdictExecution),
        (status = 500, description = "One or more components failed to roll back (failed execution).", body = super::openapi::doc::VerdictExecution),
    ),
)]
pub(crate) async fn rollback_trials<D: BlockDevice>(
    machine: Arc<dyn Machine>,
    nv: Arc<Mutex<NvStore<D>>>,
    coord: Arc<NodeCoordinator>,
    req: Option<VerdictRequest>,
) -> axum::response::Response {
    handle_verdict(machine, nv, coord, Verdict::Rollback, req).await
}

pub fn node_verdict_router<D: BlockDevice + Send + 'static>(
    machine: Arc<dyn Machine>,
    nv: Arc<Mutex<NvStore<D>>>,
    coord: Arc<NodeCoordinator>,
) -> Router {
    let commit_machine = machine.clone();
    let commit_nv = nv.clone();
    let commit_coord = coord.clone();
    Router::new()
        .route(
            "/vehicle/v1/operations/x-sumo-commit-trials/executions",
            post(move |req: Option<Json<VerdictRequest>>| {
                let machine = commit_machine.clone();
                let nv = commit_nv.clone();
                let coord = commit_coord.clone();
                async move { commit_trials(machine, nv, coord, req.map(|Json(r)| r)).await }
            }),
        )
        .route(
            "/vehicle/v1/operations/x-sumo-rollback-trials/executions",
            post(move |req: Option<Json<VerdictRequest>>| {
                let machine = machine.clone();
                let nv = nv.clone();
                let coord = coord.clone();
                async move { rollback_trials(machine, nv, coord, req.map(|Json(r)| r)).await }
            }),
        )
}

// The onboard pull-update entry lives in its own module (async, multi-
// component) — re-exported here so deployers keep one import home for the
// vendor route fragments.
pub use super::pull_update::{pull_update_router, PullUpdateRequest};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::Request;
    use machine_mgr::{
        ActivationState, Capabilities, EntityInfo, FlashCaps, LifecycleCaps, MachineRegistry,
        MachineResult, ResetKind,
    };
    use nv_store::block::MemBlockDevice;
    use nv_store::store::MIN_NV_DEVICE_SIZE;
    use nv_store::types::{NvBootState, NvUpdateSession};
    use tower::ServiceExt;

    const COMMIT_URI: &str = "/vehicle/v1/operations/x-sumo-commit-trials/executions";

    /// Minimal `Component` whose `activation_state` is fixed at construction
    /// and which counts commit/rollback calls. Only `id` + `capabilities` are
    /// required by the trait; everything else takes the `NotSupported` default.
    struct VerdictStub {
        id: &'static str,
        state: Option<ActivationState>,
        commits: AtomicUsize,
        rollbacks: AtomicUsize,
        capabilities: Capabilities,
    }

    impl VerdictStub {
        fn new(id: &'static str, supports_rollback: bool, state: Option<FlashState>) -> Self {
            Self {
                id,
                state: state.map(|s| ActivationState {
                    supports_rollback,
                    state: s,
                    active_version: None,
                    previous_version: None,
                    reset_kind: ResetKind::Local,
                }),
                commits: AtomicUsize::new(0),
                rollbacks: AtomicUsize::new(0),
                capabilities: Capabilities {
                    did_store: false,
                    flash: Some(FlashCaps {
                        dual_bank: supports_rollback,
                        supports_rollback,
                        supports_trial_boot: supports_rollback,
                        abortable_after_finalize: false,
                        reset_kind: ResetKind::Local,
                    }),
                    lifecycle: Some(LifecycleCaps {
                        restartable: false,
                        has_runtime_state: false,
                    }),
                    hsm: None,
                    dtcs: false,
                    clear_dtcs: false,
                },
            }
        }
    }

    #[async_trait]
    impl Component for VerdictStub {
        fn id(&self) -> &str {
            self.id
        }
        fn capabilities(&self) -> &Capabilities {
            &self.capabilities
        }
        async fn activation_state(&self) -> MachineResult<Option<ActivationState>> {
            Ok(self.state.clone())
        }
        async fn commit_install(&self, _id: &FlashId) -> MachineResult<()> {
            self.commits.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn rollback_install(&self, _id: &FlashId) -> MachineResult<()> {
            self.rollbacks.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn components(stubs: &[Arc<VerdictStub>]) -> Vec<Arc<dyn Component>> {
        stubs
            .iter()
            .map(|s| s.clone() as Arc<dyn Component>)
            .collect()
    }

    /// A `Machine` over the given stubs, for the router-level verdict tests.
    fn machine_with(stubs: &[Arc<VerdictStub>]) -> Arc<dyn Machine> {
        let mut builder = MachineRegistry::builder(EntityInfo {
            id: "vehicle".into(),
            name: "vehicle".into(),
            entity_type: "vehicle".into(),
            description: None,
            href: "/vehicle/v1".into(),
            status: None,
        });
        for s in stubs {
            builder = builder.with_arc(s.clone() as Arc<dyn Component>);
        }
        Arc::new(builder.build())
    }

    /// An NV store seeded with `boot` + an optional update session.
    fn nv_with(
        mut boot: NvBootState,
        session: Option<NvUpdateSession>,
    ) -> Arc<Mutex<NvStore<MemBlockDevice>>> {
        let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
        nv.write_boot_state(&mut boot).unwrap();
        if let Some(mut s) = session {
            nv.write_update_session(&mut s).unwrap();
        }
        Arc::new(Mutex::new(nv))
    }

    /// Idle: everything committed, no session (`x-sumo-update-state` = Idle).
    fn nv_idle() -> Arc<Mutex<NvStore<MemBlockDevice>>> {
        nv_with(NvBootState::default(), None)
    }

    /// RebootPending: a node reboot is owed (bit 4, vm1) — armed, not yet booted.
    fn nv_reboot_pending() -> Arc<Mutex<NvStore<MemBlockDevice>>> {
        nv_with(
            NvBootState::default(),
            Some(NvUpdateSession {
                reboot_owed: 1 << 4,
                ..Default::default()
            }),
        )
    }

    /// Trial: rebooted (no reboot owed) but vm1 (slot 4) is still uncommitted.
    fn nv_trial() -> Arc<Mutex<NvStore<MemBlockDevice>>> {
        let mut boot = NvBootState::default();
        boot.banks[4].committed = false;
        nv_with(boot, None)
    }

    fn coord() -> Arc<NodeCoordinator> {
        Arc::new(NodeCoordinator::new(Vec::new()))
    }

    /// A `POST` to `uri`, with a JSON `{"nonce": …}` body when `nonce` is set
    /// and no body at all otherwise (the old-client shape).
    fn post(uri: &str, nonce: Option<&str>) -> Request<Body> {
        let builder = Request::builder().method("POST").uri(uri);
        match nonce {
            Some(n) => builder
                .header("content-type", "application/json")
                .body(Body::from(format!(r#"{{"nonce":"{n}"}}"#)))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        }
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// The `execution_id` from one commit POST against an idle node.
    async fn commit_execution_id() -> String {
        let stub = Arc::new(VerdictStub::new("vm1", true, Some(FlashState::Committed)));
        let router = node_verdict_router(machine_with(&[stub]), nv_idle(), coord());
        let resp = router.oneshot(post(COMMIT_URI, None)).await.unwrap();
        body_json(resp).await["execution_id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn commits_only_in_trial_banked_components() {
        // A banked component in trial, a banked component already committed, a
        // singleshot (no rollback), and one with no activation concept.
        let in_trial = Arc::new(VerdictStub::new("vm1", true, Some(FlashState::Activated)));
        let already = Arc::new(VerdictStub::new("vm2", true, Some(FlashState::Committed)));
        let singleshot = Arc::new(VerdictStub::new("hsm", false, Some(FlashState::Complete)));
        let no_activation = Arc::new(VerdictStub::new("misc", false, None));
        let comps = components(&[
            in_trial.clone(),
            already.clone(),
            singleshot.clone(),
            no_activation.clone(),
        ]);

        let out = run_verdict(&comps, Verdict::Commit).await;

        assert_eq!(out.acted, vec!["vm1".to_string()]);
        assert!(out.errors.is_empty());
        assert_eq!(in_trial.commits.load(Ordering::SeqCst), 1);
        assert_eq!(already.commits.load(Ordering::SeqCst), 0);
        assert_eq!(singleshot.commits.load(Ordering::SeqCst), 0);
        assert_eq!(no_activation.commits.load(Ordering::SeqCst), 0);
        assert!(out.skipped.contains(&"vm2".to_string()));
        assert!(out.skipped.contains(&"hsm".to_string()));
        assert!(out.skipped.contains(&"misc".to_string()));
    }

    #[tokio::test]
    async fn empty_in_trial_set_is_a_noop_success() {
        // Nothing in trial (idempotent re-issue after a successful commit).
        let already = Arc::new(VerdictStub::new("vm1", true, Some(FlashState::Committed)));
        let comps = components(&[already]);
        let out = run_verdict(&comps, Verdict::Commit).await;
        assert!(out.acted.is_empty());
        assert!(out.errors.is_empty());
    }

    #[tokio::test]
    async fn rollback_acts_on_the_in_trial_set() {
        let in_trial = Arc::new(VerdictStub::new("vm1", true, Some(FlashState::Activated)));
        let comps = components(std::slice::from_ref(&in_trial));
        let out = run_verdict(&comps, Verdict::Rollback).await;
        assert_eq!(out.acted, vec!["vm1".to_string()]);
        assert_eq!(in_trial.rollbacks.load(Ordering::SeqCst), 1);
        assert_eq!(in_trial.commits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn commit_refused_while_reboot_pending() {
        // The node owes an activation reboot: the armed bank hasn't been booted,
        // so a commit must be refused (409) with the phase named — never acting
        // on the component.
        let stub = Arc::new(VerdictStub::new("vm1", true, Some(FlashState::Activated)));
        let router = node_verdict_router(
            machine_with(std::slice::from_ref(&stub)),
            nv_reboot_pending(),
            coord(),
        );

        let resp = router.oneshot(post(COMMIT_URI, None)).await.unwrap();

        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(stub.commits.load(Ordering::SeqCst), 0);
        let body = body_json(resp).await;
        assert_eq!(
            body["error"],
            "commit refused: a reboot is pending (armed bank not booted) — reset the ECU and let the trial run"
        );
    }

    #[tokio::test]
    async fn commit_proceeds_in_valid_trial() {
        // Rebooted into the trial bank (no reboot owed): the gate lets the commit
        // through and it acts on the in-trial component (existing behavior).
        let stub = Arc::new(VerdictStub::new("vm1", true, Some(FlashState::Activated)));
        let router = node_verdict_router(
            machine_with(std::slice::from_ref(&stub)),
            nv_trial(),
            coord(),
        );

        let resp = router.oneshot(post(COMMIT_URI, None)).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(stub.commits.load(Ordering::SeqCst), 1);
        assert_eq!(body_json(resp).await["result"]["committed"][0], "vm1");
    }

    #[tokio::test]
    async fn commit_proceeds_when_idle() {
        // An idle node (nothing in trial) commits as a no-op success — the gate
        // only refuses RebootPending.
        let stub = Arc::new(VerdictStub::new("vm1", true, Some(FlashState::Committed)));
        let router = node_verdict_router(machine_with(&[stub]), nv_idle(), coord());
        let resp = router.oneshot(post(COMMIT_URI, None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn echoes_client_nonce_and_omits_when_absent() {
        let stub = Arc::new(VerdictStub::new("vm1", true, Some(FlashState::Committed)));

        // A supplied nonce is echoed verbatim in the execution record.
        let router = node_verdict_router(
            machine_with(std::slice::from_ref(&stub)),
            nv_idle(),
            coord(),
        );
        let resp = router
            .oneshot(post(COMMIT_URI, Some("abc-123")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["nonce"], "abc-123");

        // No body ⇒ old-client shape: no `nonce` field.
        let router = node_verdict_router(machine_with(&[stub]), nv_idle(), coord());
        let resp = router.oneshot(post(COMMIT_URI, None)).await.unwrap();
        assert!(body_json(resp).await.get("nonce").is_none());
    }

    #[tokio::test]
    async fn mints_unique_execution_ids_per_post() {
        let id1 = commit_execution_id().await;
        let id2 = commit_execution_id().await;
        // Fresh per POST, and never the (replayable) constant op id.
        assert_ne!(id1, id2);
        assert_ne!(id1, Verdict::Commit.op_id());
    }

    // Shape-identity guards: the named response structs must serialize to the
    // exact JSON the handlers emitted as ad-hoc `serde_json::json!` before the
    // utoipa refactor (the regen test only covers the doc, not the wire).
    #[test]
    fn update_state_response_shape_is_stable() {
        let resp = UpdateStateResponse {
            phase: "RebootPending".to_string(),
            components: vec!["vm1".to_string(), "hsm".to_string()],
        };
        assert_eq!(
            serde_json::to_value(&resp).unwrap(),
            serde_json::json!({
                "phase": "RebootPending",
                "components": ["vm1", "hsm"],
            })
        );
    }

    #[test]
    fn hsm_keys_response_shape_is_stable() {
        let resp = HsmKeysResponse {
            provisioned: true,
            items: vec![
                HsmKeyEntry {
                    id: "tls-identity".to_string(),
                    kind: "EC-P256".to_string(),
                    has_certificate: true,
                    allowed_ops: Some(vec!["sign".to_string(), "verify".to_string()]),
                    public_key_der_base64: Some("QUJD".to_string()),
                },
                HsmKeyEntry {
                    id: "time-floor".to_string(),
                    kind: "monotonic".to_string(),
                    has_certificate: false,
                    allowed_ops: None,
                    public_key_der_base64: None,
                },
            ],
        };
        assert_eq!(
            serde_json::to_value(&resp).unwrap(),
            serde_json::json!({
                "provisioned": true,
                "items": [
                    {
                        "id": "tls-identity",
                        "kind": "EC-P256",
                        "has_certificate": true,
                        "allowed_ops": ["sign", "verify"],
                        "public_key_der_base64": "QUJD",
                    },
                    {
                        "id": "time-floor",
                        "kind": "monotonic",
                        "has_certificate": false,
                        "allowed_ops": null,
                        "public_key_der_base64": null,
                    },
                ],
            })
        );
    }

    #[test]
    fn csr_result_shape_is_stable() {
        let resp = CsrResult {
            key_id: "tls-identity".to_string(),
            csr_der_base64: "QUJD".to_string(),
        };
        assert_eq!(
            serde_json::to_value(&resp).unwrap(),
            serde_json::json!({
                "key_id": "tls-identity",
                "csr_der_base64": "QUJD",
            })
        );
    }
}
