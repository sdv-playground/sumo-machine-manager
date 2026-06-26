use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
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
use tokio::sync::Mutex;

use crate::config::Bank;
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
    let vms = mgr
        .list()
        .into_iter()
        .map(|v| VmInfoResponse {
            name: v.name,
            status: v.status,
            pid: v.pid,
            backend: format!("{:?}", v.backend).to_lowercase(),
        })
        .collect();
    Json(vms)
}

async fn stop_vm(State(mgr): State<SharedManager>, Path(name): Path<String>) -> impl IntoResponse {
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
        })
        .await;
    }

    // Phase 3: force-kill if needed + cleanup (fast, under lock)
    {
        let mut mgr = mgr.lock().await;
        mgr.finalize_stop(&name);
    }

    (StatusCode::OK, Json(serde_json::json!({"ok": true})))
}

/// Query params for [`ensure_vm_running`]. Optional `?bank=a|b` lets the
/// caller (component-mgr after an OTA flip) pin the A/B bank to relaunch from.
/// Absent ⇒ leave the VM's existing `def.bank` untouched (back-compat with
/// manual callers and supernova's startup auto-start).
#[derive(Debug, Default, Deserialize)]
struct EnsureParams {
    bank: Option<String>,
}

/// Idempotent "ensure VM is running with current config". Backs both
/// POST /vms/{name}/start and POST /vms/{name}/restart so callers don't
/// have to probe state first — a previously-started but never-healthy
/// instance (e.g. qvm rejected a config option and exited) gets recycled
/// instead of returning AlreadyRunning.
///
/// An optional `?bank=a|b` query pins which A/B bank to relaunch from: it's
/// pushed via `set_vm_bank` right before `start_vm`. component-mgr sends it with
/// the just-activated bank so the relaunch boots that bank instead of the
/// stale boot-time `def.bank`. Absent ⇒ `def.bank` is
/// left as-is.
///
/// `initiate_stop` is synchronous (signal + record pid; or, for an
/// already-dead handle, cleanup + return no-op handle). The blocking
/// stages (wait_for_exit, finalize_stop, start_vm) run in a background
/// task after we've returned 200, matching the documented contract
/// callers (component-mgr's notify_vm_service) rely on: "returns 200 the moment
/// the recycle is initiated (it does NOT wait for QEMU/qvm to fully boot)".
async fn ensure_vm_running(
    State(mgr): State<SharedManager>,
    Path(name): Path<String>,
    Query(params): Query<EnsureParams>,
) -> impl IntoResponse {
    // Parse the optional bank selector to vm-service's own `Bank`. Unknown
    // tokens are treated as absent (no clobber) rather than erroring — the
    // notify is best-effort and an unexpected value shouldn't block a relaunch.
    let bank = params.bank.as_deref().and_then(|s| match s {
        "a" | "A" => Some(Bank::A),
        "b" | "B" => Some(Bank::B),
        _ => None,
    });

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
                let exited =
                    tokio::task::spawn_blocking(move || manager::wait_for_exit(pid, timeout))
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
            // Pin the requested bank (if any) before launch so the relaunch
            // boots the just-activated bank. Only push when provided — an
            // absent `?bank=` must not clobber the existing `def.bank`.
            if let Some(b) = bank {
                let _ = mgr.set_vm_bank(&start_name, Some(b));
            }
            mgr.start_vm(&start_name)
        })
        .await;
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

    (
        StatusCode::OK,
        Json(serde_json::json!({"ok": true, "queued": true})),
    )
}

async fn health_vm(
    State(mgr): State<SharedManager>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let mut mgr = mgr.lock().await;
    match mgr.health_detail(&name) {
        Ok(detail) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": detail.status,
                "guest_state": detail.guest_state,
                "hb_seq": detail.hb_seq,
                "boot_id": detail.boot_id,
            })),
        ),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VmServiceConfig;
    use crate::manager::VmManager;
    use std::sync::Mutex as StdMutex;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Single dummy VM so `start_vm` runs the full launch path (verify hook +
    /// dummy runner) without real images on disk.
    fn dummy_config() -> VmServiceConfig {
        let yaml = r#"
vms:
  vm1:
    backend: dummy
    image_dir: /var/lib/vms/vm1
"#;
        serde_yaml::from_str(yaml).unwrap()
    }

    /// Build the router with a pre-launch verify hook that records the bank dir
    /// `start_vm` resolves — i.e. the effect of whatever `def.bank` was at launch.
    /// Returns (router-backing manager, last-seen bank dir cell).
    fn manager_with_seen() -> (SharedManager, Arc<StdMutex<Option<std::path::PathBuf>>>) {
        let seen: Arc<StdMutex<Option<std::path::PathBuf>>> = Arc::new(StdMutex::new(None));
        let seen_for_hook = seen.clone();
        let mgr = VmManager::with_device_transport(dummy_config(), None).with_pre_launch_verify(
            Arc::new(move |_name, bank_dir| {
                *seen_for_hook.lock().unwrap() = Some(bank_dir.to_path_buf());
                Ok(())
            }),
        );
        (Arc::new(Mutex::new(mgr)), seen)
    }

    /// Serve the router on an ephemeral loopback port; return its addr.
    async fn serve(mgr: SharedManager) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(mgr);
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        addr
    }

    /// Fire a raw `POST {path}` and read back the status line — mirrors how
    /// component-mgr's `notify_vm_service` talks to this route.
    async fn post(addr: std::net::SocketAddr, path: &str) -> String {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf[..n])
            .lines()
            .next()
            .unwrap_or("")
            .to_string()
    }

    /// Poll a closure until it returns true or the deadline passes. The route
    /// returns 200 the moment the recycle is *queued*; the bank push + launch
    /// happen in a background task, so we wait for the observable effect.
    async fn wait_until(mut cond: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if cond() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        cond()
    }

    #[tokio::test]
    async fn restart_with_bank_query_pins_bank_before_launch() {
        let (mgr, seen) = manager_with_seen();
        // Seed a different bank so the test proves the query *changed* it.
        mgr.lock().await.set_vm_bank("vm1", Some(Bank::A)).unwrap();
        let addr = serve(mgr.clone()).await;

        let status = post(addr, "/vms/vm1/restart?bank=b").await;
        assert!(status.contains("200"), "queued 200, got: {status}");

        // The background task pushes bank=B via set_vm_bank, then launches —
        // the verify hook (sync cell) observes the resolved bank_b dir once
        // the launch runs. Poll that observable effect.
        let ok = wait_until(|| seen.lock().unwrap().is_some()).await;
        assert!(ok, "verify hook should fire (background launch ran)");

        assert_eq!(
            seen.lock().unwrap().clone(),
            Some(std::path::PathBuf::from("/var/lib/vms/vm1/bank_b")),
            "verify hook must see bank_b — proving the push landed before launch"
        );
        // And def.bank itself is now B.
        assert_eq!(
            mgr.lock().await.vm_bank("vm1"),
            Some(Bank::B),
            "?bank=b must flip def.bank to Some(B)"
        );
    }

    #[tokio::test]
    async fn restart_without_bank_query_leaves_bank_unchanged() {
        let (mgr, seen) = manager_with_seen();
        // Pre-set bank A; an absent ?bank= must NOT clobber it.
        mgr.lock().await.set_vm_bank("vm1", Some(Bank::A)).unwrap();
        let addr = serve(mgr.clone()).await;

        let status = post(addr, "/vms/vm1/restart").await;
        assert!(status.contains("200"), "queued 200, got: {status}");

        // Wait for the launch to complete (verify hook fires), then confirm
        // def.bank is still A — the old/manual-caller contract.
        let ok = wait_until(|| seen.lock().unwrap().is_some()).await;
        assert!(ok, "verify hook should fire (dummy launch ran)");
        assert_eq!(
            mgr.lock().await.vm_bank("vm1"),
            Some(Bank::A),
            "absent ?bank= must leave def.bank untouched"
        );
        assert_eq!(
            seen.lock().unwrap().clone(),
            Some(std::path::PathBuf::from("/var/lib/vms/vm1/bank_a")),
        );
    }
}
