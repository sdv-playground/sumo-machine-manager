//! Onboard PULL update — the device-side campaign entry (the pull-path
//! counterpart of the push `/updates` wire).
//!
//! `POST /vehicle/v1/operations/x-sumo-pull-update/executions` receives a
//! T2-signed L1 campaign manifest (base64) + the (untrusted) CAS base URL,
//! validates the L1 against the device's pinned sw-authority anchor, resolves
//! the campaign's per-component L2 dependencies, and installs each into ITS
//! component — integrated payloads through the normal upload path,
//! content-addressed payloads fetched at finalize (the backend's per-part
//! copy-vs-fetch reconciliation). The install is long-running, so the POST
//! replies `202 Accepted` + `Location` and the client polls
//! `GET .../executions/{execution_id}` (the SOVDd `/updates` async-job shape).
//!
//! Trust model (docs/design/orchestration-convergence.md §2): the device
//! verifies the T2-signed CONTENT and the JWT OPERATION independently; the
//! caller is untrusted plumbing. Every fetched byte is bound to a
//! content-address the signed manifest committed to. Finalize stages AND
//! activates ("stage + activate, defer reboot"); the reboot and the trial
//! verdict stay with their own triggers (`x-sumo-commit-trials`).
//!
//! Vendor extension in sumo-mm, not SOVDd (the three-layer rule).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use machine_mgr::{Component, FlashSession, InstallSource, Machine, MachineError};
use puller::Puller;
use sha2::{Digest, Sha256};
use sovd_core::{OperationExecution, OperationStatus};

pub const PULL_OP_ID: &str = "x-sumo-pull-update";
pub const PULL_OP_PATH: &str = "/vehicle/v1/operations/x-sumo-pull-update/executions";

/// Body of the `x-sumo-pull-update` operation.
#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct PullUpdateRequest {
    /// Optional target assertion: when set, every dependency in the signed
    /// campaign must target this component (400 otherwise). An ASSERTION, not
    /// a filter — silently installing a subset of a signed campaign would
    /// subvert the L1 as the decision artifact.
    #[serde(default)]
    pub component: Option<String>,
    /// The T2-signed L1 campaign manifest envelope (base64 of the COSE bytes).
    /// Its dependency/payload URIs are content-addresses, so the device pins
    /// what it fetches to what the signed manifest commits to.
    pub l1_base64: String,
    /// Base URL of the content-addressed store the device pulls dependencies
    /// and payloads from. Untrusted — every fetched blob is verified against
    /// the signed content-address before use.
    pub cas_base_url: String,
}

/// Resolves the device's pinned manifest-signing trust anchor (CBOR COSE_Key)
/// per request — `None` while the device is unprovisioned, in which case the
/// route replies 503 instead of the service failing at startup.
pub type TrustAnchorSource = Arc<dyn Fn() -> Option<Vec<u8>> + Send + Sync>;

/// In-memory ledger for the async executions. Operator plumbing, not durable
/// state — the durable truth is NV (`x-sumo-update-state` + per-component
/// activation), which a restarted orchestrator polls to re-derive where it is.
#[derive(Default)]
pub(crate) struct Executions {
    map: Mutex<HashMap<String, OperationExecution>>,
    seq: AtomicU64,
}

/// Completed executions kept for late pollers before pruning.
const KEEP_COMPLETED: usize = 16;

impl Executions {
    fn next_id(&self) -> String {
        format!("pull-{}", self.seq.fetch_add(1, Ordering::Relaxed) + 1)
    }

    fn any_running(&self) -> bool {
        self.map
            .lock()
            .unwrap()
            .values()
            .any(|e| matches!(e.status, OperationStatus::Running))
    }

    fn get(&self, id: &str) -> Option<OperationExecution> {
        self.map.lock().unwrap().get(id).cloned()
    }

    /// Insert/replace an execution; prune the oldest completed entries beyond
    /// [`KEEP_COMPLETED`] (a Running entry is never pruned).
    fn put(&self, exec: OperationExecution) {
        let mut map = self.map.lock().unwrap();
        map.insert(exec.execution_id.clone(), exec);
        let mut done: Vec<(String, chrono::DateTime<chrono::Utc>)> = map
            .values()
            .filter(|e| !matches!(e.status, OperationStatus::Running))
            .map(|e| (e.execution_id.clone(), e.started_at))
            .collect();
        if done.len() > KEEP_COMPLETED {
            done.sort_by_key(|(_, at)| *at);
            let excess = done.len() - KEEP_COMPLETED;
            for (id, _) in done.into_iter().take(excess) {
                map.remove(&id);
            }
        }
    }
}

/// Build the onboard pull-update routes: the POST entry (202 + `Location`)
/// and the per-execution GET status.
///
/// Authorization is enforced **on this route** by the injected `authorizer`
/// (route-scoped — independent of whether the host wires global enforcement):
/// the POST needs an Operational `update:execute` token bound to this device
/// (`aud`), re-checked per targeted component once the campaign is resolved.
pub fn pull_update_router(
    machine: Arc<dyn Machine>,
    authorizer: Arc<dyn sovd_api::Authorizer>,
    trust_anchor: TrustAnchorSource,
) -> Router {
    let execs: Arc<Executions> = Arc::default();
    let post_execs = execs.clone();
    Router::new()
        .route(
            PULL_OP_PATH,
            post(
                move |headers: axum::http::HeaderMap, Json(req): Json<PullUpdateRequest>| {
                    let machine = machine.clone();
                    let authorizer = authorizer.clone();
                    let trust_anchor = trust_anchor.clone();
                    let execs = post_execs.clone();
                    async move {
                        handle_post(machine, authorizer, trust_anchor, execs, headers, req).await
                    }
                },
            ),
        )
        .route(
            &format!("{PULL_OP_PATH}/{{execution_id}}"),
            get(
                move |axum::extract::Path(execution_id): axum::extract::Path<String>| {
                    let execs = execs.clone();
                    async move { get_pull_update_status(execs, execution_id).await }
                },
            ),
        )
}

/// `GET /vehicle/v1/operations/x-sumo-pull-update/executions/{execution_id}` —
/// poll a pull-update execution; see [`pull_update_router`].
#[utoipa::path(
    get,
    path = "/vehicle/v1/operations/x-sumo-pull-update/executions/{execution_id}",
    tag = "x-sumo-vendor-extension",
    params(("execution_id" = String, Path, description = "The execution id returned by the POST.")),
    responses(
        (status = 200, description = "The execution's current status (running / completed / failed).", body = super::openapi::doc::OperationExecution),
        (status = 404, description = "No execution with that id.", body = String),
    ),
)]
pub(crate) async fn get_pull_update_status(
    execs: Arc<Executions>,
    execution_id: String,
) -> axum::response::Response {
    match execs.get(&execution_id) {
        Some(exec) => (StatusCode::OK, Json(exec)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            format!("no execution '{execution_id}'"),
        )
            .into_response(),
    }
}

/// The POST handler: synchronous pre-flight (auth / anchor / L1 signature /
/// integrated-dep dispatch plan / busy check — every 4xx surfaces BEFORE the
/// 202), then spawn the install task and reply `202 + Location`.
#[utoipa::path(
    post,
    path = "/vehicle/v1/operations/x-sumo-pull-update/executions",
    tag = "x-sumo-vendor-extension",
    request_body = PullUpdateRequest,
    security(("bearer" = [])),
    responses(
        (status = 202, description = "Accepted; the install runs in the background. Poll the `Location` for the execution.", body = super::openapi::doc::OperationExecution, headers(("Location" = String, description = "URL of the created execution resource."))),
        (status = 400, description = "L1 not base64, not a campaign, or an integrated dependency failed its dispatch plan.", body = String),
        (status = 401, description = "Missing or insufficient Operational update:execute token bound to this device.", body = String),
        (status = 409, description = "A pull-update execution is already running.", body = String),
        (status = 503, description = "Device not provisioned: no sw-authority trust anchor.", body = String),
    ),
)]
pub(crate) async fn handle_post(
    machine: Arc<dyn Machine>,
    authorizer: Arc<dyn sovd_api::Authorizer>,
    trust_anchor: TrustAnchorSource,
    execs: Arc<Executions>,
    headers: axum::http::HeaderMap,
    req: PullUpdateRequest,
) -> axum::response::Response {
    // (1) Device-level authorization for the op itself; per-component checks
    // re-run once the campaign's targets are known.
    let bearer = bearer_of(&headers);
    let access = sovd_api::AccessRequest {
        bearer: bearer.as_deref(),
        method: &axum::http::Method::POST,
        path: PULL_OP_PATH,
        component: None,
        capability: sovd_api::Capability::UpdateExecute,
    };
    if let Err(e) = authorizer.authorize(&access).await {
        return (StatusCode::UNAUTHORIZED, format!("unauthorized: {e}")).into_response();
    }

    // (2) The sw-authority anchor exists only once the device is provisioned.
    let Some(anchor) = trust_anchor() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "device not provisioned: no sw-authority trust anchor".to_string(),
        )
            .into_response();
    };

    // (3) Decode + T2-validate the L1 (the caller-side precondition of
    // resolve_campaign_dependencies) and require the campaign shape.
    let l1_bytes = match base64::engine::general_purpose::STANDARD.decode(&req.l1_base64) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("l1_base64 not base64: {e}"),
            )
                .into_response()
        }
    };
    let l1 = match crate::streaming::validate_l1(&l1_bytes, &anchor) {
        Ok(m) => m,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    if !l1.is_campaign() {
        return (
            StatusCode::BAD_REQUEST,
            "not a campaign manifest (no dependencies)".to_string(),
        )
            .into_response();
    }

    // (4) Dispatch plan over the INTEGRATED dependencies — unknown component
    // (404), wrong bank-set target (415), and the `component` assertion (400)
    // all surface before the 202. Remote (content-addressed) L2s are fetched
    // by the task; their routing failures surface on the execution instead.
    for idx in 0..l1.dependency_count() {
        let Some(uri) = l1.dependency_uri(idx) else {
            return (
                StatusCode::BAD_REQUEST,
                format!("campaign dependency {idx} has no uri"),
            )
                .into_response();
        };
        if !uri.starts_with('#') {
            continue;
        }
        let Some(l2) = l1.integrated_payload(uri) else {
            return (
                StatusCode::BAD_REQUEST,
                format!("campaign references integrated dependency {uri} but it is absent"),
            )
                .into_response();
        };
        if let Err((code, msg)) = plan_dep(machine.as_ref(), l2, req.component.as_deref()) {
            return (code, msg).into_response();
        }
    }

    // (5) One campaign at a time. The node update-transaction gate would 409
    // the second campaign anyway — but only after burning a start_install
    // (and its target-bank wipe); refuse it here instead.
    if execs.any_running() {
        return (
            StatusCode::CONFLICT,
            "a pull-update execution is already running".to_string(),
        )
            .into_response();
    }

    // (6) Record the execution and run the install in the background.
    let execution_id = execs.next_id();
    let started_at = chrono::Utc::now();
    let running = OperationExecution {
        execution_id: execution_id.clone(),
        operation_id: PULL_OP_ID.to_string(),
        status: OperationStatus::Running,
        result: None,
        error: None,
        started_at,
        completed_at: None,
    };
    execs.put(running.clone());
    {
        let execs = execs.clone();
        tokio::spawn(async move {
            let done = execute_pull_update(
                machine,
                authorizer,
                anchor,
                bearer,
                req,
                l1_bytes,
                execution_id,
                started_at,
            )
            .await;
            execs.put(done);
        });
    }

    (
        StatusCode::ACCEPTED,
        [(
            header::LOCATION,
            format!("{PULL_OP_PATH}/{}", running.execution_id),
        )],
        Json(running),
    )
        .into_response()
}

/// Resolve which component an L2 envelope targets, enforce the optional
/// `component` assertion, and run the dispatcher's wrong-target check
/// (`MachineError::WrongTarget` → 415, the same wire mapping as the push
/// upload path).
fn plan_dep(
    machine: &dyn Machine,
    l2_bytes: &[u8],
    assert_component: Option<&str>,
) -> Result<(String, Arc<dyn Component>), (StatusCode, String)> {
    let envelope = sumo_codec::decode::decode_envelope(l2_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("dependency is not a SUIT envelope: {e:?}"),
        )
    })?;
    let manifest = sumo_onboard::manifest::Manifest { envelope };
    let target = manifest
        .component_id(0)
        .and_then(|segs| segs.first())
        .map(|seg| String::from_utf8_lossy(seg).into_owned())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "dependency carries no component id".to_string(),
            )
        })?;
    if let Some(want) = assert_component {
        if want != target {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("campaign targets component '{target}' but the request asserts '{want}'"),
            ));
        }
    }
    let comp = machine
        .component(&target)
        .cloned()
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no component '{target}'")))?;
    if let Some(expected) = comp.bank_set() {
        crate::dispatcher::check_target(l2_bytes, expected).map_err(|e| match e {
            MachineError::WrongTarget(msg) => (StatusCode::UNSUPPORTED_MEDIA_TYPE, msg),
            other => (StatusCode::BAD_REQUEST, other.to_string()),
        })?;
    }
    Ok((target, comp))
}

/// Per-dependency progress detail folded into the execution `result`.
struct DepStep {
    component: String,
    phase: &'static str,
    error: Option<String>,
}

fn steps_json(steps: &[DepStep]) -> serde_json::Value {
    serde_json::Value::Array(
        steps
            .iter()
            .map(|s| {
                let mut o = serde_json::Map::new();
                o.insert("component".into(), serde_json::json!(s.component));
                o.insert("phase".into(), serde_json::json!(s.phase));
                if let Some(e) = &s.error {
                    o.insert("error".into(), serde_json::json!(e));
                }
                serde_json::Value::Object(o)
            })
            .collect(),
    )
}

/// Run the campaign install and return the finished execution. Public so
/// integration tests drive the full flow synchronously; the POST handler
/// spawns it.
#[allow(clippy::too_many_arguments)]
pub async fn execute_pull_update(
    machine: Arc<dyn Machine>,
    authorizer: Arc<dyn sovd_api::Authorizer>,
    trust_anchor: Vec<u8>,
    bearer: Option<String>,
    req: PullUpdateRequest,
    l1_bytes: Vec<u8>,
    execution_id: String,
    started_at: chrono::DateTime<chrono::Utc>,
) -> OperationExecution {
    let mut steps: Vec<DepStep> = Vec::new();
    let outcome = run_campaign(
        machine.as_ref(),
        authorizer.as_ref(),
        &trust_anchor,
        bearer.as_deref(),
        &req,
        &l1_bytes,
        &mut steps,
    )
    .await;

    match outcome {
        Ok(installed) => {
            tracing::info!(
                op = PULL_OP_ID,
                execution = %execution_id,
                deps = installed,
                "pull-update installed a content-addressed campaign"
            );
            OperationExecution {
                execution_id,
                operation_id: PULL_OP_ID.to_string(),
                status: OperationStatus::Completed,
                result: Some(serde_json::json!({
                    "dependencies_installed": installed,
                    "components": steps_json(&steps),
                })),
                error: None,
                started_at,
                completed_at: Some(chrono::Utc::now()),
            }
        }
        Err(error) => {
            tracing::warn!(op = PULL_OP_ID, execution = %execution_id, %error, "pull-update failed");
            OperationExecution {
                execution_id,
                operation_id: PULL_OP_ID.to_string(),
                status: OperationStatus::Failed,
                result: Some(serde_json::json!({ "components": steps_json(&steps) })),
                error: Some(error),
                started_at,
                completed_at: Some(chrono::Utc::now()),
            }
        }
    }
}

/// A staged (started + uploaded, not yet finalized) dependency.
struct Staged {
    target: String,
    comp: Arc<dyn Component>,
    session: FlashSession,
}

/// Best-effort abort of every still-open staged session (failure cleanup) —
/// releases the components' node-transaction staging so the node returns
/// toward Idle.
async fn abort_staged(staged: &[Staged]) {
    for s in staged {
        if let Err(e) = s.comp.abort_install(&s.session.id).await {
            tracing::warn!(component = %s.target, error = %e, "abort_install during pull-update cleanup failed");
        }
    }
}

/// True if any component in the L2 references a payload by non-integrated
/// URI — i.e. finalize will need the fetch fallback (and therefore the
/// component must accept an [`InstallSource`]).
fn l2_needs_fetch(l2_bytes: &[u8]) -> bool {
    let Ok(envelope) = sumo_codec::decode::decode_envelope(l2_bytes) else {
        return false;
    };
    let manifest = sumo_onboard::manifest::Manifest { envelope };
    (0..manifest.component_count()).any(|i| manifest.uri(i).is_some_and(|u| !u.starts_with('#')))
}

/// The campaign body: resolve deps → stage all (plan, per-component authz,
/// install source, start, upload) → finalize all. On failure, abort every
/// still-open session; already-finalized deps stay in trial and are reported
/// honestly (the operator resolves them via the node verdict ops).
async fn run_campaign(
    machine: &dyn Machine,
    authorizer: &dyn sovd_api::Authorizer,
    trust_anchor: &[u8],
    bearer: Option<&str>,
    req: &PullUpdateRequest,
    l1_bytes: &[u8],
    steps: &mut Vec<DepStep>,
) -> Result<usize, String> {
    // Pre-flight already T2-validated the L1; re-decode for traversal.
    let envelope =
        sumo_codec::decode::decode_envelope(l1_bytes).map_err(|e| format!("L1 decode: {e:?}"))?;
    let l1 = sumo_onboard::manifest::Manifest { envelope };

    let puller =
        Puller::new(&req.cas_base_url, trust_anchor).map_err(|e| format!("puller init: {e:?}"))?;
    let l2s = crate::streaming::resolve_campaign_dependencies(&l1, &puller)
        .await
        .map_err(|e| format!("dependency resolution: {e}"))?;

    // The campaign identity: sha256 of the signed L1 envelope. Every sibling
    // component stages under this id, Joining ONE node update transaction;
    // anything unrelated gets Mixing-refused by the gate.
    let session_id: [u8; 32] = Sha256::digest(l1_bytes).into();

    // Phase 1 — stage all: the banked group stages together before anything
    // applies (mirrors the offboard engine's stage_all / node-update design).
    let mut staged: Vec<Staged> = Vec::new();
    for (i, l2) in l2s.iter().enumerate() {
        let (target, comp) = match plan_dep(machine, l2, req.component.as_deref()) {
            Ok(x) => x,
            Err((_, msg)) => {
                steps.push(DepStep {
                    component: format!("dependency-{i}"),
                    phase: "failed",
                    error: Some(msg.clone()),
                });
                abort_staged(&staged).await;
                return Err(format!("dependency {i}: {msg}"));
            }
        };

        // Per-component authorization: the token must carry update:execute
        // for EVERY targeted component (or a wildcard scope).
        let access = sovd_api::AccessRequest {
            bearer,
            method: &axum::http::Method::POST,
            path: PULL_OP_PATH,
            component: Some(&target),
            capability: sovd_api::Capability::UpdateExecute,
        };
        if let Err(e) = authorizer.authorize(&access).await {
            steps.push(DepStep {
                component: target.clone(),
                phase: "failed",
                error: Some(format!("unauthorized: {e}")),
            });
            abort_staged(&staged).await;
            return Err(format!("dependency {i} ({target}): unauthorized: {e}"));
        }

        // Session-scoped pull source: the finalize fetch fallback + the
        // campaign session id for the node gate. A component that does not
        // support it can still install an integrated-payload L2.
        let source = InstallSource {
            cas_base_url: req.cas_base_url.clone(),
            trust_anchor: trust_anchor.to_vec(),
            session_id: Some(session_id),
        };
        match comp.set_install_source(source).await {
            Ok(()) => {}
            Err(MachineError::NotSupported(_)) if !l2_needs_fetch(l2) => {}
            Err(e) => {
                steps.push(DepStep {
                    component: target.clone(),
                    phase: "failed",
                    error: Some(format!("set_install_source: {e}")),
                });
                abort_staged(&staged).await;
                return Err(format!(
                    "dependency {i} ({target}): set_install_source: {e}"
                ));
            }
        }

        let session = match comp.start_install().await {
            Ok(s) => s,
            Err(e) => {
                steps.push(DepStep {
                    component: target.clone(),
                    phase: "failed",
                    error: Some(format!("start_install: {e}")),
                });
                abort_staged(&staged).await;
                return Err(format!("dependency {i} ({target}): start_install: {e}"));
            }
        };
        let open = Staged {
            target: target.clone(),
            comp,
            session,
        };
        if let Err(e) = open
            .comp
            .upload_envelope(&open.session.id, envelope_stream(l2.clone()))
            .await
        {
            steps.push(DepStep {
                component: target.clone(),
                phase: "failed",
                error: Some(format!("upload: {e}")),
            });
            staged.push(open); // its session is open — include it in cleanup
            abort_staged(&staged).await;
            return Err(format!("dependency {i} ({target}): upload: {e}"));
        }
        steps.push(DepStep {
            component: target,
            phase: "staged",
            error: None,
        });
        staged.push(open);
    }

    // Phase 2 — finalize all: per-part copy-vs-fetch reconciliation, IVD
    // seal, NV flip, activation (reboot deferred; verdict via the node ops).
    for (i, s) in staged.iter().enumerate() {
        if let Err(e) = s.comp.finalize_install(&s.session.id).await {
            steps[i].phase = "failed";
            steps[i].error = Some(format!("finalize: {e}"));
            // This dep and everything after it never applied — abort their
            // open sessions. Deps finalized before it stay in trial (reported
            // as "finalized"; the operator resolves via the node verdict).
            abort_staged(&staged[i..]).await;
            return Err(format!("finalize {}: {e}", s.target));
        }
        steps[i].phase = "finalized";
    }

    Ok(staged.len())
}

/// The full `Authorization` header value (`"Bearer <token>"`), if present —
/// the authorizer strips the `Bearer ` prefix itself. `pub(crate)`: the
/// admin-state router (same inline-auth pattern) shares it.
pub(crate) fn bearer_of(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// One-shot [`machine_mgr::EnvelopeStream`] over `bytes`.
fn envelope_stream(bytes: Vec<u8>) -> machine_mgr::EnvelopeStream {
    Box::pin(futures::stream::once(async move {
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(bytes::Bytes::from(bytes))
    }))
}
