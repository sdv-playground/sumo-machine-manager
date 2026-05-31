//! Reusable SOVD route fragments served by any sumo-stack deployment
//! that exposes a `Machine`.
//!
//! These vendor extensions live in sumo-mm (not SOVDd) per the
//! three-layer rule in `tasks/iso-17978-compliance.md` §1 — SOVDd stays
//! ISO 17978-3 spec-pure and replaceable.  Binaries (the `vm-sovd` bin
//! shipped here, plus closed-source variants like
//! supernova-machine-manager) merge these routes into their own router
//! to expose the same wire.

use std::sync::Arc;

use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use machine_mgr::{Machine, MachineError};

/// Build the `x-sumo-csr` route.
///
/// Wire:
///
///   `GET /vehicle/v1/components/hsm/x-sumo-csr` → 200, body = DER CSR,
///   `Content-Type: application/pkcs10`.
///
/// `x-sumo-csr` is a vendor extension per ISO 17978-3 §5.3.6.  CSR
/// retrieval is read-only — the signed device certificate that comes
/// back from the CA ships in via the standard SUIT keystore update
/// (one channel for HSM key material — see
/// `feedback_hsm_one_channel_key_material.md`).
pub fn csr_router(machine: Arc<dyn Machine>) -> Router {
    Router::new().route(
        "/vehicle/v1/components/hsm/x-sumo-csr",
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
                match comp.get_csr().await {
                    Ok(csr) => {
                        tracing::info!("CSR generated ({} bytes)", csr.0.len());
                        (
                            [(header::CONTENT_TYPE, "application/pkcs10")],
                            csr.0.to_vec(),
                        )
                            .into_response()
                    }
                    Err(MachineError::PolicyRejected(s)) => {
                        (StatusCode::FORBIDDEN, s).into_response()
                    }
                    Err(MachineError::NotSupported(_)) => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "CSR not configured".to_string(),
                    )
                        .into_response(),
                    Err(e) => {
                        tracing::error!(error = %e, "CSR generation failed");
                        (StatusCode::INTERNAL_SERVER_ERROR, format!("CSR error: {e}"))
                            .into_response()
                    }
                }
            }
        }),
    )
}
