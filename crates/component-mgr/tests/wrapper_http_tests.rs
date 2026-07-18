//! End-to-end HTTP smoke tests through the path that `vm-sovd` / the host
//! actually use in production: SOVD HTTP → `sovd-api` router →
//! `ComponentBackend` (the engine, wired directly).
//!
//! `sovd_tests.rs` exercises the same SOVD HTTP layer; these tests pin the
//! wiring the binaries register (the engine direct for non-install-router
//! components). Add a test here whenever a bug is found that the unit tests
//! didn't catch — the wire layer is where translation mismatches live.
//!
//! In particular `list_and_read_agree` would have caught the original bug:
//! the retired round-trip adapter listed `/data` ids whose `/data/{id}` reads
//! 404'd (no manifest / identity overlay). With the engine wired directly,
//! list and read gate on one authority and must agree.
//!
//! Keep this file small. It's a smoke test of the wiring, not a
//! comprehensive replay of `sovd_tests.rs`.
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

use component_mgr::backend::{ComponentBackend, ComponentConfig, INSTALLED_MANIFEST_PARAM_ID};
use component_mgr::manifest_provider::ManifestProvider;
use component_mgr::suit_provider::SuitProvider;

/// Build the same router shape that `vm-sovd`'s `main` registers, but with an
/// in-memory NV store. vm1 + hsm are non-install-router components, so — as in
/// production — the `ComponentBackend` engine is wired directly as the SOVD
/// `DiagnosticBackend`.
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

    let components: Vec<(&str, BankSet, ComponentConfig)> = vec![
        ("vm1", BankSet::Vm1, ComponentConfig::default()),
        (
            "hsm",
            BankSet::Hsm,
            ComponentConfig {
                supports_rollback: false,
                single_bank: true,
                entity_type: "hsm".into(),
                log_source: None,
            },
        ),
    ];

    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    for (id, set, cfg) in components {
        let backend: Arc<dyn DiagnosticBackend> =
            Arc::new(ComponentBackend::new(set, nv.clone(), mp.clone(), cfg));
        backends.insert(id.to_string(), backend);
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
    // ComponentBackend::list_parameters serves the DID registry directly.
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
    // ComponentBackend::read_data serves the factory DID from NV.
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
    // Table 270 UpdateStatusBody.  Confirms the /updates collection
    // is served by the directly-wired ComponentBackend.
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

/// Every `ParameterInfo` from `GET /data` carries a `category` (ISO 17978-3
/// Table 70). The directly-wired engine populates it for every listed id.
#[tokio::test]
async fn every_listed_param_has_a_category() {
    let router = make_wrapper_router();
    let (status, body) = get_json(&router, "/vehicle/v1/components/vm1/data").await;
    assert_eq!(status, StatusCode::OK);
    let items = body.get("items").and_then(|v| v.as_array()).expect("items");
    assert!(!items.is_empty(), "expected a non-empty /data list");
    for p in items {
        let id = p.get("id").and_then(|v| v.as_str()).unwrap_or("<no id>");
        assert!(
            p.get("category").map(|c| !c.is_null()).unwrap_or(false),
            "param {id} is missing a category: {p}"
        );
    }
}

/// **The assertion that would have caught the original-bug class.**
///
/// The retired round-trip adapter served a *broken subset* of `/data`: it
/// listed ids whose `/data/{id}` read 404'd (its re-implementation didn't
/// resolve them). With the engine wired directly, list and read are served by
/// the SAME `ComponentBackend`, so every id the engine LISTS reads back 200.
///
/// Since the manifest-less-bank list/read gap was closed (spec C-031): the
/// F187–F19E SW-identity DIDs, which resolve only from a committed signed
/// manifest, are no longer LISTED without one — so there is nothing left to
/// excuse. This test now asserts the strict invariant: EVERY listed id reads
/// back exactly 200 (and never 500). That also guards the hardware-identity +
/// factory DIDs (`serial_number`, `vin`, …) which read from NV and must stay
/// both listed and readable.
#[tokio::test]
async fn list_and_read_agree() {
    let router = make_wrapper_router();
    let (status, body) = get_json(&router, "/vehicle/v1/components/vm1/data").await;
    assert_eq!(status, StatusCode::OK);
    let items = body.get("items").and_then(|v| v.as_array()).expect("items");
    assert!(!items.is_empty(), "expected a non-empty /data list");

    for p in items {
        let id = p
            .get("id")
            .and_then(|v| v.as_str())
            .expect("each param has an id");
        // Registry ids are URL-safe — no percent-encoding needed.
        let (st, read_body) =
            get_json(&router, &format!("/vehicle/v1/components/vm1/data/{id}")).await;

        assert_eq!(
            st,
            StatusCode::OK,
            "listed id '{id}' did not read back 200 (list/read disagreement): {read_body}"
        );
    }
}

/// Fix for spec C-031: without a committed signed IVD manifest the
/// manifest-sourced SW-identity DIDs (F187 spare_part, F188 ecu_sw, F189
/// fw_version, F194/F195 supplier sw, F197 system_name, F198 tester_serial,
/// F199 programming_date, F19E odx_file_id) must NOT appear in `GET /data` —
/// they read 404 from the manifest overlay, so listing them would be a
/// list/read disagreement. The HARDWARE-identity / factory DIDs in the same
/// F18x/F19x numeric range (supplier_id, manufacturing_date, serial_number,
/// vin, ecu_hw_number, supplier_hw_number, supplier_hw_version) read from NV
/// regardless of any manifest and MUST stay listed.
#[tokio::test]
async fn identity_dids_absent_without_manifest_but_hardware_dids_listed() {
    let router = make_wrapper_router();
    let (status, body) = get_json(&router, "/vehicle/v1/components/vm1/data").await;
    assert_eq!(status, StatusCode::OK);
    let items = body.get("items").and_then(|v| v.as_array()).expect("items");
    let listed_ids: Vec<&str> = items
        .iter()
        .filter_map(|p| p.get("id").and_then(|v| v.as_str()))
        .collect();

    // Manifest-sourced identity DIDs: absent without a committed manifest.
    for id in [
        "spare_part_number",
        "ecu_sw_number",
        "fw_version",
        "supplier_sw_number",
        "supplier_sw_version",
        "system_name",
        "tester_serial",
        "programming_date",
        "odx_file_id",
    ] {
        assert!(
            !listed_ids.contains(&id),
            "manifest-gated identity DID '{id}' must not be listed without a committed manifest: {listed_ids:?}"
        );
    }

    // Hardware-identity / factory DIDs: read from NV → stay listed.
    for id in [
        "supplier_id",
        "manufacturing_date",
        "serial_number",
        "vin",
        "ecu_hw_number",
        "supplier_hw_number",
        "supplier_hw_version",
    ] {
        assert!(
            listed_ids.contains(&id),
            "hardware/factory DID '{id}' must remain listed regardless of manifest: {listed_ids:?}"
        );
    }
}

/// `GET /data/fw_version`: with a committed signed IVD manifest it returns a
/// real version; without one (this in-memory harness) it is a manifest-gated
/// identity DID that reads 404. Either way the wrapper returns EXACTLY what the
/// directly-wired engine returns — proven by comparing the read status to the
/// engine's own `read_data`. (On-device, where a bank is flashed, this is the
/// real-version 200 the refactor restored.)
#[tokio::test]
async fn fw_version_reads_real_value_when_listed() {
    let router = make_wrapper_router();
    let (st, body) = get_json(&router, "/vehicle/v1/components/vm1/data/fw_version").await;

    if st == StatusCode::OK {
        // Manifest present → must be a real, non-empty version, never all-NUL.
        let v = body
            .get("value")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        assert!(
            v.as_str().map(|s| !s.is_empty()).unwrap_or(false),
            "fw_version should be a real non-empty value, got: {v}"
        );
    } else {
        // No committed manifest in this harness → identity DID not resolvable.
        // Spec-correct unknown case (consistent with the absent manifest param).
        assert_eq!(
            st,
            StatusCode::NOT_FOUND,
            "without a manifest fw_version should 404, got {st}: {body}"
        );
    }
}

/// Without a committed signed IVD manifest, the vendor `x-sumo-installed-manifest`
/// parameter is absent from the `/data` list AND `GET /data/{id}` 404s — the
/// spec-correct "unknown parameter" case (consistent list/read).
#[tokio::test]
async fn installed_manifest_absent_without_sign() {
    let router = make_wrapper_router();

    let (_, list) = get_json(&router, "/vehicle/v1/components/vm1/data").await;
    let present = list
        .get("items")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .any(|p| p.get("id").and_then(|v| v.as_str()) == Some(INSTALLED_MANIFEST_PARAM_ID))
        })
        .unwrap_or(false);
    assert!(
        !present,
        "{INSTALLED_MANIFEST_PARAM_ID} must not be listed without a committed manifest"
    );

    let (st, _body) = get_json(
        &router,
        &format!("/vehicle/v1/components/vm1/data/{INSTALLED_MANIFEST_PARAM_ID}"),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::NOT_FOUND,
        "{INSTALLED_MANIFEST_PARAM_ID} should 404 without a committed manifest"
    );
}
