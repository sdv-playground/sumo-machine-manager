use super::*;

// ---------------------------------------------------------------------------
// Guest health (via vm-service HTTP API)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct GuestHealth {
    pub guest_state: u32,
    pub hb_seq: u32,
    /// Random per-guest-lifetime id from the heartbeat wire format. Surfaced in
    /// `/status` `x-runtime.boot_id` — the orchestrator's reboot witness: a
    /// *changed* boot_id confirms a fresh post-reset lifetime, not stale shmem
    /// from the previous one (qvm-shmem regions persist across stop/start).
    pub boot_id: u32,
    /// Coarse health status string ("running" / "stopped" / "unhealthy").
    /// ComponentBackend treats anything not "running" as not-yet-activated —
    /// captures the stale-heartbeat case (vm-service flips to
    /// "unhealthy" after 5s of stuck seq) without duplicating that
    /// timeout here.
    pub status: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PreResetHealth {
    Running(u32),
    NotRunning,
}

pub(super) enum VmHealthState {
    Running(GuestHealth),
    NotRunning,
}

impl VmHealthState {
    pub(super) fn baseline(&self) -> PreResetHealth {
        match self {
            Self::Running(health) => PreResetHealth::Running(health.boot_id),
            Self::NotRunning => PreResetHealth::NotRunning,
        }
    }

    pub(super) fn running(self) -> Option<GuestHealth> {
        match self {
            Self::Running(health) => Some(health),
            Self::NotRunning => None,
        }
    }
}

/// Synthesise a [`GuestHealth`] snapshot for a component that has no
/// vm-service backing (e.g. activator-backed components like RT/M7).
/// Called from `ComponentBackend::read_data` when `vm_service_addr` is None.
///
/// Implementations should be cheap (the call lands on the SOVD read-data
/// hot path served by the campaign viewer). Internal caching is fine
/// when the underlying source is expensive (`m7loader -q` shells out).
pub trait HealthProbe: Send + Sync {
    fn probe(&self) -> Option<GuestHealth>;

    /// Extra per-component metadata for the `/status` `x-runtime` block —
    /// the ONE uniform per-component metadata node. Probe-specific facts
    /// (e.g. the M7 platform-loader counters) ride here; never a bespoke
    /// per-component route. Standard fields win on key collision, and the
    /// same cheapness contract as [`Self::probe`] applies (cache internally).
    fn runtime_extensions(&self) -> serde_json::Map<String, serde_json::Value> {
        serde_json::Map::new()
    }
}

/// Query vm-service health endpoint via TCP loopback.
/// Returns guest_state and hb_seq from the JSON response.
/// Query vm-service's `/vms/<name>/health` endpoint over TCP loopback.
///
/// **Async** intentionally: `component-mgr` runs on the same tokio runtime as
/// vm-service (the host embeds both). A blocking `std::net::TcpStream`
/// call inside an `async fn` parks an entire tokio worker for up to the
/// 2-second read timeout, which is observable as "every other SOVD DID
/// read takes 2s" when workers are scarce (e.g. the 2-core S32G3).
/// Using `tokio::net::TcpStream` keeps the worker available — the await
/// suspension lets other futures run while we wait on I/O.
pub(super) async fn query_vm_health(addr: &str, vm_name: &str) -> Option<GuestHealth> {
    query_vm_health_state(addr, vm_name)
        .await
        .ok()
        .and_then(VmHealthState::running)
}

/// Query the same endpoint as [`query_vm_health`] but keep the FULL observation
/// — including the not-running cases, which `VmHealthState` collapses to a unit
/// variant and `query_vm_health` drops entirely.
///
/// `Ok(None)` = vm-service does not know this VM (HTTP 404). That is distinct
/// from `Ok(Some(lifecycle))` where the lifecycle says `stopped`: one means
/// "not configured", the other "configured and deliberately down".
pub(super) async fn query_vm_lifecycle(
    addr: &str,
    vm_name: &str,
) -> Result<Option<GuestLifecycle>, String> {
    match health_response(addr, vm_name).await? {
        Some(json) => GuestLifecycle::from_json(&json).map(Some),
        None => Ok(None),
    }
}

/// Legacy strict view, kept bit-for-bit: `NotRunning` for a stopped VM or a
/// 404, `Err` when a VM that reports itself non-stopped is missing any part of
/// the heartbeat triple.
///
/// That last rule looks like an accident but is load-bearing at exactly one
/// call site — `ecu_reset` refuses to establish a reset baseline it cannot
/// trust (a `starting` guest with no heartbeat yet has no `boot_id`, so there
/// is nothing to compare a post-reset reading against). Preserved here rather
/// than "fixed" so this change alters no control flow; revisit it with the
/// orchestrator wait in step 4.
pub(super) async fn query_vm_health_state(
    addr: &str,
    vm_name: &str,
) -> Result<VmHealthState, String> {
    let Some(lifecycle) = query_vm_lifecycle(addr, vm_name).await? else {
        return Ok(VmHealthState::NotRunning);
    };
    if lifecycle.is_down() {
        return Ok(VmHealthState::NotRunning);
    }
    Ok(VmHealthState::Running(GuestHealth {
        guest_state: lifecycle
            .guest_state
            .ok_or_else(|| "running health response missing guest_state".to_string())?,
        hb_seq: lifecycle
            .hb_seq
            .ok_or_else(|| "running health response missing hb_seq".to_string())?,
        boot_id: lifecycle
            .boot_id
            .ok_or_else(|| "running health response missing boot_id".to_string())?,
        status: lifecycle.status,
    }))
}

/// `GET /vms/{name}/health` over TCP loopback. `Ok(None)` on HTTP 404.
pub(super) async fn health_response(
    addr: &str,
    vm_name: &str,
) -> Result<Option<serde_json::Value>, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    // Cap connect+read at 2 s combined. Both ends are on loopback so a
    // healthy vm-service responds in microseconds; this timeout is a
    // ceiling on misbehaviour.
    let deadline = std::time::Duration::from_secs(2);

    let mut stream = tokio::time::timeout(deadline, TcpStream::connect(addr))
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|e| format!("connect failed: {e}"))?;

    let request = format!(
        "GET /vms/{vm_name}/health HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n"
    );
    tokio::time::timeout(deadline, stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| "write timed out".to_string())?
        .map_err(|e| format!("write failed: {e}"))?;

    let mut buf = Vec::with_capacity(1024);
    tokio::time::timeout(deadline, stream.read_to_end(&mut buf))
        .await
        .map_err(|_| "read timed out".to_string())?
        .map_err(|e| format!("read failed: {e}"))?;
    let response = std::str::from_utf8(&buf).map_err(|e| format!("invalid HTTP response: {e}"))?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| "invalid HTTP response: missing header terminator".to_string())?;
    let status_code = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| "invalid HTTP response status".to_string())?;
    if status_code == 404 {
        return Ok(None);
    }
    if status_code != 200 {
        return Err(format!("health endpoint returned HTTP {status_code}"));
    }

    serde_json::from_str(body)
        .map(Some)
        .map_err(|e| format!("invalid health JSON: {e}"))
}
