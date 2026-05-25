/// HTTP API for VM lifecycle control.
///
/// Routes:
///   GET  /vms                → list all VMs + status
///   POST /vms/{name}/start   → ensure VM is running (idempotent: stops any
///                              existing instance first, then starts fresh)
///   POST /vms/{name}/stop    → stop a VM
///   POST /vms/{name}/restart → alias for /start (kept for API back-compat)
///   GET  /vms/{name}/health  → health status

use std::sync::Arc;
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
};
use serde::Serialize;
use tokio::sync::Mutex;

use crate::health_status::HealthStatus;
use crate::manager::{self, ManagerError, VmManager};

type SharedManager = Arc<Mutex<VmManager>>;

pub fn router(manager: SharedManager) -> Router {
    Router::new()
        .route("/vms", get(list_vms))
        .route("/vms/{name}/start", post(ensure_vm_running))
        .route("/vms/{name}/stop", post(stop_vm))
        .route("/vms/{name}/restart", post(ensure_vm_running))
        .route("/vms/{name}/health", get(health_vm))
        .layer(axum::middleware::from_fn(log_request))
        .with_state(manager)
}

async fn log_request(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    // Demoted from INFO to DEBUG — supernova polls /vms/<vm>/health for
    // every component every second, so logging both the request and
    // response at INFO floods supernova.log at ~16 lines/sec (≈ 14 MB/day
    // per running VM). Errors and 4xx/5xx still show via tracing in the
    // route handlers; this trace is only useful for development.
    tracing::debug!(target: "vm_service::api", %method, %uri, "vm-service request");
    let resp = next.run(req).await;
    tracing::debug!(target: "vm_service::api", status = %resp.status(), "vm-service response");
    resp
}

#[derive(Serialize)]
struct VmInfoResponse {
    name: String,
    status: HealthStatus,
    pid: Option<u32>,
    backend: String,
}

async fn list_vms(State(mgr): State<SharedManager>) -> Json<Vec<VmInfoResponse>> {
    let mut mgr = mgr.lock().await;
    let vms = mgr.list().into_iter().map(|v| VmInfoResponse {
        name: v.name,
        status: v.status,
        pid: v.pid,
        backend: format!("{:?}", v.backend).to_lowercase(),
    }).collect();
    Json(vms)
}

async fn stop_vm(
    State(mgr): State<SharedManager>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    // Phase 1: signal shutdown (fast, under lock)
    let stop_handle = {
        let mut mgr = mgr.lock().await;
        match mgr.initiate_stop(&name) {
            Ok(sh) => sh,
            Err(e) => return error_response(e),
        }
    };
    // Lock is released here — health/list remain responsive

    // Phase 2: wait for process to exit (blocking, NO lock held)
    if let Some(pid) = stop_handle.pid {
        let timeout = stop_handle.timeout_secs;
        let _ = tokio::task::spawn_blocking(move || {
            // bool return is "exited cleanly?"; finalize_stop force-kills
            // on false, so the result is informational here. Caller logs
            // its own elapsed metric.
            manager::wait_for_exit(pid, timeout)
        }).await;
    }

    // Phase 3: force-kill if needed + cleanup (fast, under lock)
    {
        let mut mgr = mgr.lock().await;
        mgr.finalize_stop(&name);
    }

    (StatusCode::OK, Json(serde_json::json!({"ok": true})))
}

/// Idempotent "ensure VM is running with current config". Backs both
/// POST /vms/{name}/start and POST /vms/{name}/restart so callers don't
/// have to probe state first — a previously-started but never-healthy
/// instance (e.g. qvm rejected a config option and exited) gets recycled
/// instead of returning AlreadyRunning.
///
/// `initiate_stop` is synchronous (signal + record pid; or, for an
/// already-dead handle, cleanup + return no-op handle). The blocking
/// stages (wait_for_exit, finalize_stop, start_vm) run in a background
/// task after we've returned 200, matching the documented contract
/// callers (vm-mgr's notify_vm_service) rely on: "returns 200 the moment
/// the recycle is initiated (it does NOT wait for QEMU/qvm to fully boot)".
async fn ensure_vm_running(
    State(mgr): State<SharedManager>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let stop_handle = {
        let mut mgr = mgr.lock().await;
        match mgr.initiate_stop(&name) {
            Ok(sh) => Some(sh),
            Err(ManagerError::NotRunning(_)) => None,
            Err(e) => return error_response(e),
        }
    };

    let mgr_clone = mgr.clone();
    let name_clone = name.clone();
    tokio::spawn(async move {
        // Per-phase timing so a stuck restart is greppable in the log.
        // Resolution is whole seconds — matches operator intuition;
        // sub-second jitter on Linux shutdown isn't actionable.
        let total_started = std::time::Instant::now();

        if let Some(sh) = stop_handle {
            if let Some(pid) = sh.pid {
                let timeout = sh.timeout_secs;
                let phase_started = std::time::Instant::now();
                let exited = tokio::task::spawn_blocking(move || {
                    manager::wait_for_exit(pid, timeout)
                })
                .await
                .unwrap_or(false);
                let elapsed_secs = phase_started.elapsed().as_secs();
                if exited {
                    tracing::info!(
                        vm = %name_clone, elapsed_secs,
                        "ensure_vm_running: guest shutdown completed"
                    );
                } else {
                    tracing::warn!(
                        vm = %name_clone, elapsed_secs, timeout_secs = timeout,
                        "ensure_vm_running: guest shutdown timed out — will force-kill"
                    );
                }
            }
            let mut mgr = mgr_clone.lock().await;
            mgr.finalize_stop(&name_clone);
        }

        let phase_started = std::time::Instant::now();
        let start_name = name_clone.clone();
        let start_mgr = mgr_clone.clone();
        let result = tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Handle::current();
            let mut mgr = rt.block_on(start_mgr.lock());
            mgr.start_vm(&start_name)
        }).await;
        let start_elapsed_secs = phase_started.elapsed().as_secs();

        let total_elapsed_secs = total_started.elapsed().as_secs();
        match result {
            Ok(Ok(())) => tracing::info!(
                vm = %name_clone, start_elapsed_secs, total_elapsed_secs,
                "ensure_vm_running: VM is running"
            ),
            Ok(Err(e)) => tracing::error!(
                vm = %name_clone, start_elapsed_secs, total_elapsed_secs, error = %e,
                "ensure_vm_running: background start_vm failed"
            ),
            Err(e) => tracing::error!(
                vm = %name_clone, start_elapsed_secs, total_elapsed_secs, error = %e,
                "ensure_vm_running: background task panicked"
            ),
        }
    });

    (StatusCode::OK, Json(serde_json::json!({"ok": true, "queued": true})))
}

async fn health_vm(
    State(mgr): State<SharedManager>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let mut mgr = mgr.lock().await;
    match mgr.health_detail(&name) {
        Ok(detail) => (StatusCode::OK, Json(serde_json::json!({
            "status": detail.status,
            "guest_state": detail.guest_state,
            "hb_seq": detail.hb_seq,
            "boot_id": detail.boot_id,
        }))),
        Err(e) => error_response(e),
    }
}

fn error_response(e: ManagerError) -> (StatusCode, Json<serde_json::Value>) {
    let (code, msg) = match &e {
        ManagerError::NotFound(_) => (StatusCode::NOT_FOUND, e.to_string()),
        ManagerError::AlreadyRunning(_) => (StatusCode::CONFLICT, e.to_string()),
        ManagerError::NotRunning(_) => (StatusCode::CONFLICT, e.to_string()),
        ManagerError::Runner(_) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    (code, Json(serde_json::json!({"error": msg})))
}
