//! Per-component administrative state (disable/enable) — the SOVD vendor op.
//!
//! `POST /vehicle/v1/components/{id}/operations/x-sumo-admin-state/executions`
//! body `{"state": "enabled" | "disabled", "reason"?: string}` → synchronous
//! ISO 17978-3 §7.14 `OperationExecution` whose `result` carries
//! `{state, reboot_required}`.
//!
//! ISO 17978 has no home for a *persistent* administrative disable (§7.19
//! start/shutdown is runtime-lifecycle only; modes are the CDA set; §7.17
//! locks expire), so this is a spec-sanctioned vendor extension (§5.4.5) —
//! living here in sumo-mm, never in SOVDd (the three-layer rule). Read-back is
//! the `admin_state` field in `/status`'s `x-sumo-runtime` extensions block
//! (tri-state: absent = not disableable).
//!
//! Semantics (enforced by `ComponentBackend::set_admin_state`):
//! - unknown component → 404; non-disableable → 400; disable admitted only
//!   when idle (committed + no owing node transaction) → else 409;
//!   idempotent repeats → 200 no-op.
//! - flag persists FIRST, then the runtime is enacted via the component's
//!   `Deactivator`; an enact failure keeps the component disabled and is
//!   reported as `status: failed` in the execution body (HTTP 200 — the
//!   state change itself succeeded), mirroring the trials response shape.
//!
//! Authorization is **on this route** (pull-update pattern B): the handler
//! builds an `AccessRequest { component, capability: ComponentAdmin }` against
//! the injected `Authorizer`, so no `route_capability` edit exists anywhere.
//! Verb `component-admin`, Operational tier (reversible).

use std::sync::Arc;

use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use machine_mgr::{AdminStateOutcome, Machine, MachineError};
use sovd_core::{OperationExecution, OperationStatus};

use super::pull_update::bearer_of;

pub const ADMIN_STATE_OP_ID: &str = "x-sumo-admin-state";

/// Body of the `x-sumo-admin-state` operation.
#[derive(serde::Deserialize)]
pub struct AdminStateRequest {
    /// The requested persisted state: `"enabled"` | `"disabled"`.
    pub state: String,
    /// Optional operator-supplied reason — logged as the audit breadcrumb,
    /// not persisted.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Build the admin-state route. Deployments merge this next to the other
/// vendor fragments (`gateway_router` does; the host machine manager merges
/// it after `create_router`).
pub fn admin_state_router(
    machine: Arc<dyn Machine>,
    authorizer: Arc<dyn sovd_api::Authorizer>,
) -> Router {
    Router::new().route(
        &format!(
            "/vehicle/v1/components/{{component_id}}/operations/{ADMIN_STATE_OP_ID}/executions"
        ),
        post(
            move |Path(component_id): Path<String>,
                  headers: axum::http::HeaderMap,
                  Json(req): Json<AdminStateRequest>| {
                let machine = machine.clone();
                let authorizer = authorizer.clone();
                async move { handle_post(machine, authorizer, headers, component_id, req).await }
            },
        ),
    )
}

/// The POST handler: parse → authorize (inline) → resolve component → execute
/// synchronously → §7.14 execution body.
async fn handle_post(
    machine: Arc<dyn Machine>,
    authorizer: Arc<dyn sovd_api::Authorizer>,
    headers: axum::http::HeaderMap,
    component_id: String,
    req: AdminStateRequest,
) -> axum::response::Response {
    // (1) Parse the requested state up front — malformed input never reaches
    // the authorizer or the machine.
    let disable = match req.state.as_str() {
        "disabled" => true,
        "enabled" => false,
        other => {
            return (
                StatusCode::BAD_REQUEST,
                format!("state must be \"enabled\" or \"disabled\", got {other:?}"),
            )
                .into_response()
        }
    };

    // (2) Route-scoped authorization: `component-admin` verb + component
    // scope. No token at all → 401; a presented token that fails
    // verification or lacks the verb/scope → 403.
    let bearer = bearer_of(&headers);
    let path =
        format!("/vehicle/v1/components/{component_id}/operations/{ADMIN_STATE_OP_ID}/executions");
    let access = sovd_api::AccessRequest {
        bearer: bearer.as_deref(),
        method: &axum::http::Method::POST,
        path: &path,
        component: Some(&component_id),
        capability: sovd_api::Capability::ComponentAdmin,
    };
    if let Err(e) = authorizer.authorize(&access).await {
        let code = if bearer.is_none() {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::FORBIDDEN
        };
        return (code, format!("unauthorized: {e}")).into_response();
    }

    // (3) Resolve the target — unknown component → 404.
    let Some(comp) = machine.component(&component_id).cloned() else {
        return (
            StatusCode::NOT_FOUND,
            format!("no component '{component_id}'"),
        )
            .into_response();
    };

    tracing::info!(
        op = ADMIN_STATE_OP_ID,
        component = %component_id,
        state = %req.state,
        reason = req.reason.as_deref().unwrap_or("-"),
        "administrative state change requested"
    );

    // (4) Execute synchronously (the disable stop is bounded by the guest
    // shutdown window; the §7.14 body is the whole story — no async job).
    match comp.set_admin_state(disable).await {
        Ok(outcome) => execution_response(&outcome),
        // Absence of a Deactivator IS "cannot be disabled" — a caller error
        // (400), not a server one.
        Err(MachineError::NotSupported(_)) => (
            StatusCode::BAD_REQUEST,
            "component does not support administrative disable".to_string(),
        )
            .into_response(),
        // Not idle (in trial / staging / owing the node reboot) — transient,
        // resolve the transaction and retry.
        Err(MachineError::Busy(msg)) => (StatusCode::CONFLICT, msg).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Render the outcome as an ISO 17978-3 §7.14 operation execution (the
/// trials-verdict response shape). HTTP 200 even when the *enact* step
/// failed: the persisted state change succeeded (flag-first ordering), and
/// the body reports the honest `failed` status + error.
fn execution_response(outcome: &AdminStateOutcome) -> axum::response::Response {
    let failed = outcome.enact_error.is_some();
    let now = chrono::Utc::now();
    let body = OperationExecution {
        execution_id: ADMIN_STATE_OP_ID.to_string(),
        operation_id: ADMIN_STATE_OP_ID.to_string(),
        status: if failed {
            OperationStatus::Failed
        } else {
            OperationStatus::Completed
        },
        result: Some(serde_json::json!({
            "state": if outcome.disabled { "disabled" } else { "enabled" },
            "reboot_required": outcome.reboot_required,
        })),
        error: outcome.enact_error.clone(),
        started_at: now,
        completed_at: Some(now),
    };
    (StatusCode::OK, Json(body)).into_response()
}
