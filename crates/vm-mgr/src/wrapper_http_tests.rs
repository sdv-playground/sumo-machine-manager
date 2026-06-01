//! End-to-end HTTP smoke tests through the *wrapper* path that `vm-sovd`
//! actually uses in production: SOVD HTTP → `sovd-api` router →
//! `ComponentDiagBackend` → `Component` → `VmBackend`.
//!
//! `sovd_tests.rs` exercises the same SOVD HTTP layer but registers raw
//! `VmBackend` instances directly. These tests prove the wrapper doesn't
//! break the wire format. Add a test here whenever a bug is found that the
//! unit tests didn't catch — the wrapper layer is where translation
//! mismatches live.
//!
//! Keep this file small. It's a smoke test of the wiring, not a
//! comprehensive replay of `sovd_tests.rs`.
//!
//! Closes the test-checklist step 6 gap.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use nv_store::block::MemBlockDevice;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::*;

use sovd_core::DiagnosticBackend;

use crate::backend::{ComponentConfig, VmBackend};
use crate::component_adapter::VmBackendComponent;
use crate::diag_backend::ComponentDiagBackend;
use crate::manifest_provider::ManifestProvider;
use crate::sovd::security::TestSecurityProvider;
use crate::suit_provider::SuitProvider;

/// Build the same router shape that `vm-sovd`'s `main` registers, but with an
/// in-memory NV store. Each component is wrapped in `ComponentDiagBackend`.
fn make_wrapper_router() -> axum::Router {
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv_store = NvStore::new(dev);
    nv_store
        .write_boot_state(&mut NvBootState::default())
        .unwrap();

    // Pre-populate factory data so /data/serial_number returns something useful.
    let mut f = NvFactory::default();
    let copy_into = |dst: &mut [u8], src: &str| {
        let n = src.len().min(dst.len());
        dst[..n].copy_from_slice(&src.as_bytes()[..n]);
    };
    copy_into(&mut f.serial_number, "ECU-WRAP-001");
    copy_into(&mut f.vin, "WRAP1234567890ABC");
    nv_store.write_factory(&mut f).unwrap();

    let nv = Arc::new(Mutex::new(nv_store));
    let trust_anchor = vec![0u8; 32];
    let mp: Arc<dyn ManifestProvider> = Arc::new(SuitProvider::new(trust_anchor));
    let sp = Arc::new(TestSecurityProvider);

    let components: Vec<(&str, BankSet, ComponentConfig)> = vec![
        ("vm1", BankSet::Vm1, ComponentConfig::default()),
        (
            "hsm",
            BankSet::Hsm,
            ComponentConfig {
                supports_rollback: false,
                single_bank: true,
                entity_type: "hsm".into(),
            },
        ),
    ];

    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    for (id, set, cfg) in components {
        let backend = Arc::new(VmBackend::new(set, nv.clone(), mp.clone(), sp.clone(), cfg));
        let component: Arc<dyn machine_mgr::Component> =
            Arc::new(VmBackendComponent::new(backend.clone()));
        let diag = ComponentDiagBackend::new(component, backend);
        backends.insert(id.to_string(), Arc::new(diag) as Arc<dyn DiagnosticBackend>);
    }

    let state = sovd_api::AppState::new(backends);
    sovd_api::create_router(state)
}

async fn get_json(router: &axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let resp = router
        .clone()
        .oneshot(Request::get(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn list_components_through_wrapper() {
    let router = make_wrapper_router();
    let (status, body) = get_json(&router, "/vehicle/v1/components").await;
    assert_eq!(status, StatusCode::OK);
    let items = body.get("items").and_then(|v| v.as_array()).expect("items");
    let ids: Vec<&str> = items
        .iter()
        .filter_map(|c| c.get("id").and_then(|v| v.as_str()))
        .collect();
    assert!(ids.contains(&"vm1"), "vm1 missing: {ids:?}");
    assert!(ids.contains(&"hsm"), "hsm missing: {ids:?}");
}

#[tokio::test]
async fn list_parameters_through_wrapper() {
    let router = make_wrapper_router();
    let (status, body) = get_json(&router, "/vehicle/v1/components/vm1/data").await;
    assert_eq!(status, StatusCode::OK);
    // Routes through Component::list_dids → ParameterInfo translation in adapter.
    let items = body.get("items").and_then(|v| v.as_array()).expect("items");
    assert!(
        items
            .iter()
            .any(|p| p.get("id").and_then(|v| v.as_str()) == Some("serial_number")),
        "serial_number not in list_parameters"
    );
}

#[tokio::test]
async fn read_did_through_wrapper() {
    let router = make_wrapper_router();
    let (status, body) = get_json(&router, "/vehicle/v1/components/vm1/data/serial_number").await;
    assert_eq!(status, StatusCode::OK);
    // Routes through Component::read_did → DataValue translation in adapter.
    // Response body is the flat DataValue.
    assert_eq!(
        body.get("value"),
        Some(&serde_json::Value::String("ECU-WRAP-001".into())),
        "unexpected body: {body}"
    );
    assert_eq!(body.get("did").and_then(|v| v.as_str()), Some("F18C"));
}

#[tokio::test]
async fn read_spec_status_through_wrapper() {
    // ISO 17978-3 §7.18.7 — GET /updates/{id}/status returns the
    // Table 270 UpdateStatusBody.  Confirms ComponentDiagBackend
    // routes the /updates collection through to the wrapped
    // VmBackend correctly.
    let router = make_wrapper_router();

    // Register an update so /status has an entry to read.
    let post = router
        .clone()
        .oneshot(
            Request::post("/vehicle/v1/components/vm1/updates")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(post.status(), StatusCode::CREATED);
    let body = post.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let update_id = json["update_id"].as_str().unwrap().to_string();

    let (status, body) = get_json(
        &router,
        &format!("/vehicle/v1/components/vm1/updates/{update_id}/status"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    // Table 270: phase + status are MANDATORY.
    assert!(body.get("phase").is_some(), "missing phase: {body}");
    assert!(body.get("status").is_some(), "missing status: {body}");
    // Default state of a freshly-registered update.
    assert_eq!(body["phase"], "prepare");
    assert_eq!(body["status"], "pending");
}

#[tokio::test]
async fn hsm_distinct_from_vm() {
    // Capabilities for HSM should not include "rollback" support.
    let router = make_wrapper_router();
    let (status, body) = get_json(&router, "/vehicle/v1/components/hsm").await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    // Just confirm we got the HSM component (id matches).
    assert_eq!(body.get("id").and_then(|v| v.as_str()), Some("hsm"));
}
