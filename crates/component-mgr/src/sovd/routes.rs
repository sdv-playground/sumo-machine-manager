//! Reusable SOVD route fragments served by any sumo-stack deployment
//! that exposes a `Machine`.
//!
//! These vendor extensions live in sumo-mm (not SOVDd) per the
//! three-layer rule in `tasks/iso-17978-compliance.md` §1 — SOVDd stays
//! ISO 17978-3 spec-pure and replaceable.  Binaries (the `vm-sovd` bin
//! shipped here, plus closed-source variants like
//! supernova-machine-manager) merge these routes into their own router
//! to expose the same wire.

use std::sync::{Arc, Mutex};

use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use machine_mgr::node_update::{Durable, NodeCoordinator};
use machine_mgr::{Component, FlashId, FlashState, Machine, MachineError};
use nv_store::block::BlockDevice;
use nv_store::store::NvStore;
use nv_store::types::NUM_BANK_SETS;
use puller::Puller;
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
            async move {
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
                let st = coord.node_update_state(&durable, &in_trial);
                Json(serde_json::json!({
                    "phase": st.phase.as_str(),
                    "components": st.components,
                }))
            }
        }),
    )
}

/// Build the HSM component's SOVD vendor surface — the key-slot data resource
/// and the CSR operation.
///
/// Wire:
///
///   `GET  /vehicle/v1/components/hsm/data/keys`
///        → 200 JSON `{ "provisioned": bool, "items": [ { id, key_type,
///          has_certificate, allowed_ops, public_key_der_base64 } ] }` — ALWAYS
///          served (device-generated keys exist from first boot); `provisioned`
///          is the device's own state, so callers read it instead of inferring
///          from a status code. Public-only; `public_key_der_base64` is the SPKI
///          for asymmetric slots, `null` for symmetric.
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
/// NOTE: this is machine-level SOVD surface that happens to live in the
/// `vm-mgr` crate — see `project_vm_mgr_outgrew_its_name` (rename pending).
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

/// `GET …/hsm/data/keys` — the key-slot inventory (public metadata only).
async fn hsm_keys_list(machine: Arc<dyn Machine>) -> axum::response::Response {
    let Some(comp) = machine.component("hsm") else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "no hsm component".to_string(),
        )
            .into_response();
    };
    match comp.list_keys().await {
        Ok(inv) => {
            let items: Vec<_> = inv
                .keys
                .into_iter()
                .map(|k| {
                    use base64::Engine;
                    let public_key_der_base64 = k
                        .public_key
                        .as_ref()
                        .map(|der| base64::engine::general_purpose::STANDARD.encode(der));
                    serde_json::json!({
                        "id": k.key_id,
                        "key_type": k.key_type,
                        "has_certificate": k.has_certificate,
                        "allowed_ops": k.allowed_ops,
                        "public_key_der_base64": public_key_der_base64,
                    })
                })
                .collect();
            Json(serde_json::json!({ "provisioned": inv.provisioned, "items": items }))
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
#[derive(serde::Deserialize)]
struct CsrRequest {
    key_id: String,
}

/// `POST …/hsm/operations/x-sumo-csr/executions` — sign a PKCS#10 CSR for the
/// requested slot and return it (DER, base64) in an operation execution.
async fn hsm_csr_execute(machine: Arc<dyn Machine>, req: CsrRequest) -> axum::response::Response {
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
                result: Some(serde_json::json!({
                    "key_id": req.key_id,
                    "csr_der_base64": der_b64,
                })),
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
fn verdict_response(verdict: Verdict, out: VerdictOutcome) -> axum::response::Response {
    let failed = !out.errors.is_empty();
    let mut result = serde_json::Map::new();
    result.insert(
        verdict.acted_key().to_string(),
        serde_json::json!(out.acted),
    );
    result.insert("skipped".to_string(), serde_json::json!(out.skipped));
    let now = chrono::Utc::now();
    let body = OperationExecution {
        execution_id: verdict.op_id().to_string(),
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
    (code, Json(body)).into_response()
}

async fn handle_verdict(machine: Arc<dyn Machine>, verdict: Verdict) -> axum::response::Response {
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
    verdict_response(verdict, out)
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
pub fn node_verdict_router(machine: Arc<dyn Machine>) -> Router {
    let commit = machine.clone();
    Router::new()
        .route(
            "/vehicle/v1/operations/x-sumo-commit-trials/executions",
            post(move || {
                let machine = commit.clone();
                async move { handle_verdict(machine, Verdict::Commit).await }
            }),
        )
        .route(
            "/vehicle/v1/operations/x-sumo-rollback-trials/executions",
            post(move || {
                let machine = machine.clone();
                async move { handle_verdict(machine, Verdict::Rollback).await }
            }),
        )
}

// =============================================================================
// Onboard PULL update — the device-side counterpart of the push `/updates` wire
// =============================================================================

/// Body of the `x-sumo-pull-update` operation.
#[derive(serde::Deserialize)]
pub struct PullUpdateRequest {
    /// Target component id to install the campaign into.
    pub component: String,
    /// The T2-signed L1 campaign manifest envelope (base64 of the COSE bytes).
    /// Its dependency/payload URIs are content-addresses, so the device pins
    /// what it fetches to what the signed manifest commits to.
    pub l1_base64: String,
    /// Base URL of the content-addressed store the device pulls dependencies
    /// from. Untrusted — every fetched blob is verified against the signed
    /// content-address before use.
    pub cas_base_url: String,
}

const PULL_OP_ID: &str = "x-sumo-pull-update";
const PULL_OP_PATH: &str = "/vehicle/v1/operations/x-sumo-pull-update/executions";

/// Build the onboard pull-update route.
///
/// `POST /vehicle/v1/operations/x-sumo-pull-update/executions` body
/// [`PullUpdateRequest`] → fetch a content-addressed campaign and install it
/// into the target component.
///
/// Authorization is enforced **on this route** by the injected `authorizer`
/// (route-scoped — independent of whether the host wires global enforcement):
/// the op needs an Operational `update:execute` token bound to this device
/// (`aud`) and the target component. SOVDd stays untouched — this is an
/// `x-sumo` vendor extension in sumo-mm (the three-layer rule). `trust_anchor`
/// is the device's pinned manifest-signing key (CBOR COSE_Key), used to verify
/// every fetched dependency.
pub fn pull_update_router(
    machine: Arc<dyn Machine>,
    authorizer: Arc<dyn sovd_api::Authorizer>,
    trust_anchor: Vec<u8>,
) -> Router {
    Router::new().route(
        PULL_OP_PATH,
        post(
            move |headers: axum::http::HeaderMap, Json(req): Json<PullUpdateRequest>| {
                let machine = machine.clone();
                let authorizer = authorizer.clone();
                let trust_anchor = trust_anchor.clone();
                async move {
                    let Some(comp) = machine.component(&req.component) else {
                        return (
                            StatusCode::NOT_FOUND,
                            format!("no component '{}'", req.component),
                        )
                            .into_response();
                    };
                    let bearer = bearer_of(&headers);
                    match run_pull_update(
                        &comp,
                        authorizer.as_ref(),
                        &trust_anchor,
                        bearer.as_deref(),
                        &req,
                    )
                    .await
                    {
                        Ok(exec) => {
                            let code = if matches!(exec.status, OperationStatus::Failed) {
                                StatusCode::INTERNAL_SERVER_ERROR
                            } else {
                                StatusCode::OK
                            };
                            (code, Json(exec)).into_response()
                        }
                        Err((code, msg)) => (code, msg).into_response(),
                    }
                }
            },
        ),
    )
}

/// The full `Authorization` header value (`"Bearer <token>"`), if present — the
/// authorizer strips the `Bearer ` prefix itself.
fn bearer_of(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Authorize, then pull a content-addressed campaign and install every resolved
/// dependency into `comp` via its install lifecycle. Returns the ISO 17978-3
/// §7.14 operation execution, or an HTTP error for auth/decoding failures
/// (operational failures come back as a `Failed` execution).
///
/// The CAS is untrusted: `resolve_campaign_dependencies` binds each fetched L2
/// to the sha the signed L1 committed to, and the component's `upload_envelope`
/// re-validates each L2 (signature + security version) before applying it.
pub async fn run_pull_update(
    comp: &Arc<dyn Component>,
    authorizer: &dyn sovd_api::Authorizer,
    trust_anchor: &[u8],
    bearer: Option<&str>,
    req: &PullUpdateRequest,
) -> Result<OperationExecution, (StatusCode, String)> {
    use sovd_api::{AccessRequest, Capability};

    // (1) Authorize: Operational `update:execute`, bound to this device (aud)
    // and scoped to the target component.
    let access = AccessRequest {
        bearer,
        method: &axum::http::Method::POST,
        path: PULL_OP_PATH,
        component: Some(&req.component),
        capability: Capability::UpdateExecute,
    };
    authorizer
        .authorize(&access)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("unauthorized: {e}")))?;

    // (2) Decode the signed L1 campaign manifest.
    use base64::Engine;
    let l1_bytes = base64::engine::general_purpose::STANDARD
        .decode(&req.l1_base64)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("l1_base64 not base64: {e}"),
            )
        })?;
    let envelope = sumo_codec::decode::decode_envelope(&l1_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("L1 is not a SUIT envelope: {e:?}"),
        )
    })?;
    let manifest = sumo_onboard::manifest::Manifest { envelope };

    // (3) Pull + content-address-verify the campaign dependencies.
    let now = chrono::Utc::now();
    let puller = match Puller::new(&req.cas_base_url, trust_anchor) {
        Ok(p) => p,
        Err(e) => return Ok(pull_failed(now, format!("puller init: {e:?}"))),
    };
    let l2s = match crate::streaming::resolve_campaign_dependencies(&manifest, &puller).await {
        Ok(l2s) => l2s,
        Err(e) => return Ok(pull_failed(now, format!("dependency resolution: {e:?}"))),
    };

    // (4) Install each resolved dependency into the target component. Its
    // `upload_envelope` validates each L2 inline and `finalize_install` applies.
    let session = match comp.start_install().await {
        Ok(s) => s,
        Err(e) => return Ok(pull_failed(now, format!("start_install: {e}"))),
    };
    for (i, l2) in l2s.iter().enumerate() {
        if let Err(e) = comp
            .upload_envelope(&session.id, envelope_stream(l2.clone()))
            .await
        {
            return Ok(pull_failed(now, format!("upload dependency {i}: {e}")));
        }
    }
    if let Err(e) = comp.finalize_install(&session.id).await {
        return Ok(pull_failed(now, format!("finalize_install: {e}")));
    }

    tracing::info!(
        op = PULL_OP_ID,
        component = %req.component,
        deps = l2s.len(),
        "pull-update installed a content-addressed campaign"
    );
    Ok(OperationExecution {
        execution_id: PULL_OP_ID.to_string(),
        operation_id: PULL_OP_ID.to_string(),
        status: OperationStatus::Completed,
        result: Some(serde_json::json!({
            "component": req.component,
            "dependencies_installed": l2s.len(),
        })),
        error: None,
        started_at: now,
        completed_at: Some(chrono::Utc::now()),
    })
}

fn pull_failed(now: chrono::DateTime<chrono::Utc>, error: String) -> OperationExecution {
    tracing::warn!(op = PULL_OP_ID, %error, "pull-update failed");
    OperationExecution {
        execution_id: PULL_OP_ID.to_string(),
        operation_id: PULL_OP_ID.to_string(),
        status: OperationStatus::Failed,
        result: None,
        error: Some(error),
        started_at: now,
        completed_at: Some(chrono::Utc::now()),
    }
}

/// One-shot [`machine_mgr::EnvelopeStream`] over `bytes`.
fn envelope_stream(bytes: Vec<u8>) -> machine_mgr::EnvelopeStream {
    Box::pin(futures::stream::once(async move {
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(bytes::Bytes::from(bytes))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use machine_mgr::{
        ActivationState, Capabilities, FlashCaps, LifecycleCaps, MachineResult, ResetKind,
    };

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
}
