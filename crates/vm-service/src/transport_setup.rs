//! Helper for constructing the configured `DeviceTransport` and spawning
//! its accompanying server if any.
//!
//! Lives here (in vm-service's lib) so both the `vm-service` binary and
//! the host machine manager (which embeds `VmManager` in-process) can
//! share one code path. Without this, we'd duplicate the match-on-config
//! logic across both call sites and drift over time.
//!
//! The returned `Arc<dyn DeviceTransport>` is then passed to
//! `VmManager::new`. The transport's HTTP server (when applicable) runs
//! on a tokio task tied to the current runtime — drop the runtime to
//! shut it down. There's deliberately no graceful shutdown handle today;
//! vm-service / the host are long-lived processes and the OS reaps the
//! listener when the process exits.

use std::sync::Arc;

use vm_devices::transport::http::HttpTransport;
#[cfg(target_os = "linux")]
use vm_devices::transport::ivshmem::IvshmemTransport;
use vm_devices::transport::DeviceTransport;

use crate::config::DeviceTransportConfig;

/// Build a `DeviceTransport` from configured `kind`. Returns `None` when
/// no transport is configured. Caller passes the result into
/// `VmManager::new(config, device_transport)`.
///
/// Must be called from within a tokio runtime for the HTTP variant — it
/// spawns the axum server on the current `Handle`. Synchronous (does not
/// `.await`) so it can be called inline from a `#[tokio::main]` body.
pub async fn build_device_transport(
    cfg: Option<DeviceTransportConfig>,
) -> Option<Arc<dyn DeviceTransport>> {
    match cfg {
        Some(DeviceTransportConfig::Http { bind }) => {
            let rt = tokio::runtime::Handle::current();
            let transport = Arc::new(HttpTransport::new(rt));
            let router = transport.router();
            match tokio::net::TcpListener::bind(&bind).await {
                Ok(listener) => {
                    tracing::info!("device-transport HTTP listening on {bind}");
                    tokio::spawn(async move {
                        if let Err(e) = axum::serve(listener, router).await {
                            tracing::error!("device-transport server exited: {e}");
                        }
                    });
                    Some(transport as Arc<dyn DeviceTransport>)
                }
                Err(e) => {
                    tracing::error!(
                        "failed to bind device-transport HTTP on {bind}: {e} — VMs with \
                         health devices will run without liveness monitoring"
                    );
                    None
                }
            }
        }
        #[cfg(target_os = "linux")]
        Some(DeviceTransportConfig::Ivshmem { base_dir }) => {
            tracing::info!("device-transport ivshmem under {}", base_dir.display());
            Some(Arc::new(IvshmemTransport::with_base_dir(base_dir)) as Arc<dyn DeviceTransport>)
        }
        #[cfg(not(target_os = "linux"))]
        Some(DeviceTransportConfig::Ivshmem { .. }) => {
            tracing::error!(
                "ivshmem device-transport not available on this platform — \
                 use kind: http instead"
            );
            None
        }
        Some(DeviceTransportConfig::QvmShmem { .. }) => {
            // QvmShmemTransport links libhyp.a (proprietary QNX SDP) and
            // therefore lives in the host machine manager / qnx-devices,
            // not here. The embedding binary detects this variant in its
            // own startup, constructs the transport, and passes it to
            // VmManager::with_device_transport(...) instead of going
            // through VmManager::new() which calls into this function.
            //
            // Reaching this branch from VmManager::new() means the
            // embedding binary forgot to handle qvm-shmem — log loudly
            // and run without device transport so VMs at least start.
            tracing::warn!(
                "device_transport kind=qvm-shmem requires platform-specific \
                 construction — embedding binary must call \
                 VmManager::with_device_transport directly. Falling through \
                 to no-transport mode (heartbeat / power channels disabled)."
            );
            None
        }
        None => {
            tracing::warn!(
                "no device_transport configured — VMs with health devices will run \
                 without liveness monitoring (heartbeat reads return None)"
            );
            None
        }
    }
}
