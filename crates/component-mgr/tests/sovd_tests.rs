//! Integration tests for ComponentBackend via sovd-api.
//!
//! These test the full HTTP flow through sovd-api's router, ensuring
//! our DiagnosticBackend implementation works correctly with the
//! standard SOVD REST API.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use machine_mgr::node_update::NodeCoordinator;
use machine_mgr::{
    DeactivateError, DeactivateOutcome, Deactivator, EntityInfo, InMemorySelectorStore,
    MachineRegistry, SharedSystemBankState, SystemBankManager, TestSigner,
};
use nv_store::block::MemBlockDevice;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::*;

use sovd_core::{DiagnosticBackend, FlashState};

use component_mgr::backend::{ComponentBackend, ComponentConfig};
use component_mgr::bank_provider::IvdBankProvider;
use component_mgr::component_adapter::ComponentAdapter;
use component_mgr::manifest_provider::ManifestProvider;
use component_mgr::suit_provider::SuitProvider;

use sumo_crypto::{CryptoBackend, RustCryptoBackend};
use sumo_offboard::keygen;
use sumo_offboard::ImageManifestBuilder;

// --- Test helpers ---

struct TestKeys {
    signing_key: sumo_offboard::CoseKey,
    trust_anchor: Vec<u8>,
}

fn generate_test_keys() -> TestKeys {
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let trust_anchor = signing_key.public_key_bytes();
    TestKeys {
        signing_key,
        trust_anchor,
    }
}

fn make_test_suit_envelope(keys: &TestKeys, component: &str, seq: u64, image: &[u8]) -> Vec<u8> {
    let crypto = RustCryptoBackend::new();
    let digest = crypto.sha256(image);
    ImageManifestBuilder::new()
        .signing_time(1_700_000_000)
        .component_id(vec![component.to_string()])
        .sequence_number(seq)
        .payload_digest(&digest, image.len() as u64)
        .payload_uri("#firmware".to_string())
        .integrated_payload("#firmware".to_string(), image.to_vec())
        .build(&keys.signing_key)
        .unwrap()
}

/// Like `make_test_suit_envelope`, but sets the SUIT text fields
/// (model name, version, description) so the `/updates` catalog detail
/// (`describe_update_package`) has something to enrich from.
fn make_test_suit_envelope_with_text(
    keys: &TestKeys,
    component: &str,
    seq: u64,
    image: &[u8],
    model_name: &str,
    version: &str,
    description: &str,
) -> Vec<u8> {
    let crypto = RustCryptoBackend::new();
    let digest = crypto.sha256(image);
    ImageManifestBuilder::new()
        .signing_time(1_700_000_000)
        .component_id(vec![component.to_string()])
        .sequence_number(seq)
        .payload_digest(&digest, image.len() as u64)
        .payload_uri("#firmware".to_string())
        .integrated_payload("#firmware".to_string(), image.to_vec())
        .text_model_name(model_name)
        .text_version(version)
        .text_description(description)
        .build(&keys.signing_key)
        .unwrap()
}

fn make_router() -> (axum::Router, Arc<Mutex<NvStore<MemBlockDevice>>>, TestKeys) {
    let keys = generate_test_keys();
    let suit_provider = SuitProvider::new(keys.trust_anchor.clone());
    // In tests, same key is both provisioning authority and software authority
    suit_provider.update_keys(keys.trust_anchor.clone(), None, None);
    let manifest_provider: Arc<dyn ManifestProvider> = Arc::new(suit_provider);

    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    let mut boot_state = NvBootState::default();
    nv.write_boot_state(&mut boot_state).unwrap();
    let nv = Arc::new(Mutex::new(nv));

    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    let components: Vec<(&str, BankSet, ComponentConfig)> = vec![
        (
            "host",
            BankSet::Os,
            ComponentConfig {
                entity_type: "host_os".into(),
                ..ComponentConfig::default()
            },
        ),
        ("vm1", BankSet::Vm1, ComponentConfig::default()),
        ("vm2", BankSet::Vm2, ComponentConfig::default()),
        (
            "hsm",
            BankSet::Hsm,
            ComponentConfig {
                supports_rollback: false,
                single_bank: true,
                entity_type: "hsm".into(),
                log_sources: Vec::new(),
                test_agent_url: None,
                diag_agent_url: None,
                host_diagnostics: false,
            },
        ),
    ];
    for (id, set, config) in components {
        // Thread the configured id like the factory does (`build_component` ->
        // `with_id(spec.id)`), so the fixture exercises spec.id winning over the
        // bank-set table — the invariant `os_component_wire_id_is_host` guards.
        let backend = ComponentBackend::new(set, nv.clone(), manifest_provider.clone(), config)
            .with_id(id.to_string());
        backends.insert(id.to_string(), Arc::new(backend));
    }

    let state = sovd_api::AppState::new(backends);
    let router = sovd_api::create_router(state);
    (router, nv, keys)
}

async fn get(router: &axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
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

async fn put_json(
    router: &axum::Router,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::put(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn post_json(
    router: &axum::Router,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::post(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn delete(router: &axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let resp = router
        .clone()
        .oneshot(Request::delete(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn put_bytes(
    router: &axum::Router,
    uri: &str,
    data: Vec<u8>,
) -> (StatusCode, serde_json::Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::put(uri)
                .header("content-type", "application/octet-stream")
                .body(Body::from(data))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn put_empty(router: &axum::Router, uri: &str) -> (StatusCode, axum::http::HeaderMap) {
    let resp = router
        .clone()
        .oneshot(Request::put(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let _ = resp.into_body().collect().await;
    (status, headers)
}

/// Poll `GET /updates/{id}/status` until `(phase, status)` matches a
/// terminal state for the in-process spec wire (PUT prepare / execute /
/// commit return 202; the actual backend work runs in a tokio task).
/// Returns the final body.
async fn poll_status_until_terminal(
    router: &axum::Router,
    component: &str,
    update_id: &str,
) -> serde_json::Value {
    for _ in 0..400 {
        let (status, body) = get(
            router,
            &format!("/vehicle/v1/components/{component}/updates/{update_id}/status"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        if matches!(body["status"].as_str(), Some("completed") | Some("failed")) {
            return body;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("status never reached terminal")
}

/// Poll until the orchestrated execute task pauses at substate=awaiting-verdict.
async fn poll_status_until_awaiting_verdict(
    router: &axum::Router,
    component: &str,
    update_id: &str,
) -> serde_json::Value {
    for _ in 0..400 {
        let (status, body) = get(
            router,
            &format!("/vehicle/v1/components/{component}/updates/{update_id}/status"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        if body["x-ota-substate"].as_str() == Some("awaiting-verdict")
            || matches!(body["status"].as_str(), Some("completed") | Some("failed"))
        {
            return body;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("status never reached awaiting-verdict")
}

// ============================================================
// Health & Components
// ============================================================

#[tokio::test]
async fn health_check() {
    let (router, _, _) = make_router();
    let resp = router
        .clone()
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn list_components() {
    let (router, _, _) = make_router();
    let (status, json) = get(&router, "/vehicle/v1/components").await;
    assert_eq!(status, StatusCode::OK);
    let items = json["items"].as_array().unwrap();
    assert_eq!(items.len(), 4);
}

#[tokio::test]
async fn get_component_vm1() {
    let (router, _, _) = make_router();
    let (status, json) = get(&router, "/vehicle/v1/components/vm1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["id"], "vm1");
    // Native SOVD server — the UDS session/security (seed/key) surface is
    // retired; writes are authorized by the JWT bearer at the sovd-api layer.
    assert!(!json["capabilities"]["sessions"].as_bool().unwrap());
    assert!(!json["capabilities"]["security"].as_bool().unwrap());
    assert!(json["capabilities"]["software_update"].as_bool().unwrap());
}

#[tokio::test]
async fn os_component_wire_id_is_host() {
    // Regression guard for the host-os split-brain (field 2026-08-17): the OS
    // component's wire id MUST be the configured spec.id ("host"), never the
    // internal bank-set table's "host-os". The factory threads spec.id via
    // `ComponentBackend::with_id` (mirrored in make_router); assert both wire
    // surfaces the harness reaches — the registry listing and the entity body.
    let (router, _, _) = make_router();

    let (status, json) = get(&router, "/vehicle/v1/components").await;
    assert_eq!(status, StatusCode::OK);
    let ids: Vec<&str> = json["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["id"].as_str())
        .collect();
    assert!(ids.contains(&"host"), "registry ids = {ids:?}");
    assert!(!ids.contains(&"host-os"), "leaked bank-set id: {ids:?}");

    // Entity body id — where the bank-set table used to override spec.id.
    let (status, json) = get(&router, "/vehicle/v1/components/host").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["id"], "host");
}

// ============================================================
// Data / Parameters
// ============================================================

#[tokio::test]
async fn list_parameters() {
    let (router, _, _) = make_router();
    let (status, json) = get(&router, "/vehicle/v1/components/vm1/data").await;
    assert_eq!(status, StatusCode::OK);
    let items = json["items"].as_array().unwrap();
    // vm1 here has no vm-service (health DIDs filtered) and no committed
    // manifest, so the 9 manifest-sourced SW-identity DIDs (F187–F19E) are NOT
    // listed (C-031: they'd 404 on read). What remains is the 7 hardware/factory
    // DIDs + 5 dynamic DIDs that read from NV regardless.
    assert!(items.len() >= 12, "got {} params", items.len());
}

#[tokio::test]
async fn read_active_bank() {
    let (router, _, _) = make_router();
    let (status, json) = get(&router, "/vehicle/v1/components/vm1/data/active_bank").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["value"], "A");
}

#[tokio::test]
async fn read_committed() {
    let (router, _, _) = make_router();
    let (status, json) = get(&router, "/vehicle/v1/components/vm1/data/committed").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["value"], true);
}

// ============================================================
// Session / Security — retired surface
// ============================================================

#[tokio::test]
async fn session_security_modes_retired() {
    // Native SOVD server: privileged /updates writes are authorized by the
    // JWT bearer token at the sovd-api layer (ISO 17978-3 §5.4.4); in-vehicle
    // UDS seed/key unlock is transparent server-side in the UDS-device
    // handler (SOVDd). The classic session → seed/key dance is gone: both
    // mode routes answer the DiagnosticBackend default (NotSupported → 501).
    let (router, _, _) = make_router();
    for uri in [
        "/vehicle/v1/components/vm1/modes/session",
        "/vehicle/v1/components/vm1/modes/security",
    ] {
        let (status, _) = get(&router, uri).await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "GET {uri}");
    }
    let (status, _) = put_json(
        &router,
        "/vehicle/v1/components/vm1/modes/session",
        serde_json::json!({"value": "programming"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    let (status, _) = put_json(
        &router,
        "/vehicle/v1/components/vm1/modes/security",
        serde_json::json!({"value": "level1_requestseed"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
}

// ============================================================
// Flash full flow
// ============================================================

#[tokio::test]
async fn flash_full_suit_flow() {
    // Spec-wire round trip — register the update, upload the SUIT
    // envelope as the `manifest` part, drive prepare + execute(orchestrated),
    // then commit via the Phase B vendor verb.  Asserts every transition.
    // No mode preamble: the UDS session/security dance is retired.
    let (router, _, keys) = make_router();

    let image = vec![0xBB; 2048];
    let envelope = make_test_suit_envelope(&keys, "vm1", 2, &image);

    // 1. POST /updates — server allocates update_id and calls
    //    backend.start_flash up-front (puts ComponentBackend in
    //    AwaitingManifest so the upload goes through the staging
    //    pipeline, not the legacy integrated-envelope path).
    let (status, body) = post_json(
        &router,
        "/vehicle/v1/components/vm1/updates",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "register_update: {body}");
    let update_id = body["update_id"].as_str().unwrap().to_string();

    // 2. PUT /bulk-data/manifest — uploads the SUIT envelope.  By
    //    convention the manifest is named "manifest" so the server's
    //    verify path can find it.
    let (status, _) = put_bytes(
        &router,
        &format!("/vehicle/v1/components/vm1/updates/{update_id}/bulk-data/manifest"),
        envelope,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // 3. PUT /prepare — async 202; poll /status to terminal.
    let (status, _) = put_empty(
        &router,
        &format!("/vehicle/v1/components/vm1/updates/{update_id}/prepare"),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let prepared = poll_status_until_terminal(&router, "vm1", &update_id).await;
    assert_eq!(
        prepared["phase"], "prepare",
        "after PUT /prepare: {prepared}"
    );
    assert_eq!(
        prepared["status"], "completed",
        "after PUT /prepare: {prepared}"
    );

    // 4. PUT /execute?x-ota-control=orchestrated — banked ComponentBackend
    //    runs finalize+validate+activate then pauses at
    //    substate=awaiting-verdict.
    let (status, _) = put_empty(
        &router,
        &format!(
            "/vehicle/v1/components/vm1/updates/{update_id}/execute?x-ota-control=orchestrated"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let paused = poll_status_until_awaiting_verdict(&router, "vm1", &update_id).await;
    assert_eq!(paused["phase"], "execute");
    assert_eq!(paused["status"], "inProgress");
    assert_eq!(paused["x-ota-substate"], "awaiting-verdict");

    // 5. PUT /x-ota-commit — Phase B vendor verb.  Wakes the paused
    //    execute task; calls backend.commit_flash; transitions to
    //    execute/completed.
    let (status, _) = put_empty(
        &router,
        &format!("/vehicle/v1/components/vm1/updates/{update_id}/x-ota-commit"),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let final_body = poll_status_until_terminal(&router, "vm1", &update_id).await;
    assert_eq!(final_body["phase"], "execute");
    assert_eq!(final_body["status"], "completed");
    assert!(final_body.get("x-ota-substate").is_none());
}

// ============================================================
// Update catalog detail (ISO 17978-3 §7.18.3 Table 261)
// ============================================================

#[tokio::test]
async fn get_update_detail_enriched_from_suit_manifest() {
    // Phase 4: GET /updates/{id} is enriched from the uploaded SUIT
    // manifest (update_name + updated/affected components) instead of the
    // SUIT-agnostic default (update_name == the register-time id).
    let (router, _, keys) = make_router();

    let image = vec![0xCC; 2048];
    let envelope = make_test_suit_envelope_with_text(
        &keys,
        "vm1",
        3,
        &image,
        "Sumo VM1 Firmware",
        "4.2.0",
        "Quarterly security rollup",
    );

    // Register the update (server allocates the id + opens a flash session).
    let (status, body) = post_json(
        &router,
        "/vehicle/v1/components/vm1/updates",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "register_update: {body}");
    let update_id = body["update_id"].as_str().unwrap().to_string();

    // Upload the SUIT envelope as the `manifest` part — this is where the
    // backend parses + caches the Table-261 facts keyed by the part file_id.
    let (status, _) = put_bytes(
        &router,
        &format!("/vehicle/v1/components/vm1/updates/{update_id}/bulk-data/manifest"),
        envelope,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // GET /updates/{id} → describe_update_package → enriched descriptor.
    let (status, detail) = get(
        &router,
        &format!("/vehicle/v1/components/vm1/updates/{update_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "GET /updates/{{id}}: {detail}");

    // id is unchanged (still the register-time URL key).
    assert_eq!(detail["id"], update_id);

    // update_name is enriched from SUIT text (model name + version) — and
    // is NOT the bare id default.
    assert_eq!(detail["update_name"], "Sumo VM1 Firmware 4.2.0");
    assert_ne!(detail["update_name"], serde_json::json!(update_id));

    // notes carries the SUIT text description.
    assert_eq!(detail["notes"], "Quarterly security rollup");

    // The SUIT-named component shows up as updated + affected (entity-path).
    assert_eq!(
        detail["updated_components"],
        serde_json::json!(["/vehicle/v1/components/vm1"])
    );
    assert_eq!(
        detail["affected_components"],
        serde_json::json!(["/vehicle/v1/components/vm1"])
    );
}

// ============================================================
// Faults
// ============================================================

#[tokio::test]
async fn faults_empty_initially() {
    let (router, _, _) = make_router();
    let (status, json) = get(&router, "/vehicle/v1/components/vm1/faults").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["total_count"], 0);
}

#[tokio::test]
async fn faults_and_clear() {
    let (router, nv, _) = make_router();
    // Write a DTC directly
    {
        let mut nv = nv.lock().unwrap();
        let bs = nv.read_boot_state().unwrap();
        let active = bs.banks[BankSet::Vm1.as_index()].active_bank;
        let mut runtime = nv.read_runtime(BankSet::Vm1, active).unwrap_or_default();
        runtime.dtc_count = 1;
        runtime.dtcs[0] = DtcEntry {
            dtc_number: 0x00A301,
            status: 0x01,
        };
        nv.write_runtime(BankSet::Vm1, active, &mut runtime)
            .unwrap();
    }

    let (status, json) = get(&router, "/vehicle/v1/components/vm1/faults").await;
    assert_eq!(status, StatusCode::OK);
    let items = json["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);

    // Clear — ISO 17978-3 §7.8 fault.delete returns 204 No Content
    // (Phase E quick-win 1 in SOVDd; the JSON body was non-spec).
    let (status, _) = delete(&router, "/vehicle/v1/components/vm1/faults").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

// ============================================================
// OTA via direct API (commit/rollback without flash upload)
// ============================================================

/// Drive register + manifest upload + prepare + orchestrated execute, leaving
/// the component paused at `awaiting-verdict`: its bank is ARMED (uncommitted,
/// next-boot pointer flipped) and the activation reboot has NOT happened yet.
/// Returns the update id, for the verdict verb that follows.
async fn flash_to_awaiting_verdict(
    router: &axum::Router,
    component: &str,
    envelope: Vec<u8>,
) -> String {
    let (status, body) = post_json(
        router,
        &format!("/vehicle/v1/components/{component}/updates"),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "register_update: {body}");
    let update_id = body["update_id"].as_str().unwrap().to_string();

    let (status, _) = put_bytes(
        router,
        &format!("/vehicle/v1/components/{component}/updates/{update_id}/bulk-data/manifest"),
        envelope,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _) = put_empty(
        router,
        &format!("/vehicle/v1/components/{component}/updates/{update_id}/prepare"),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let prepared = poll_status_until_terminal(router, component, &update_id).await;
    assert_eq!(prepared["status"], "completed", "prepare: {prepared}");

    let (status, _) = put_empty(
        router,
        &format!(
            "/vehicle/v1/components/{component}/updates/{update_id}\
             /execute?x-ota-control=orchestrated"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    poll_status_until_awaiting_verdict(router, component, &update_id).await;
    update_id
}

/// Drive a full prepare+execute+verdict cycle and return the
/// post-verdict `UpdateStatusBody`.  `verdict_verb` is one of
/// `x-ota-commit` / `x-ota-rollback`.
async fn run_spec_cycle(
    router: &axum::Router,
    component: &str,
    envelope: Vec<u8>,
    verdict_verb: &str,
) -> serde_json::Value {
    let update_id = flash_to_awaiting_verdict(router, component, envelope).await;

    let (status, _) = put_empty(
        router,
        &format!("/vehicle/v1/components/{component}/updates/{update_id}/{verdict_verb}"),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    poll_status_until_terminal(router, component, &update_id).await
}

#[tokio::test]
async fn ota_commit_via_sovd() {
    let (router, _, keys) = make_router();
    let envelope = make_test_suit_envelope(&keys, "vm1", 3, &vec![0xCC; 1024]);
    let final_body = run_spec_cycle(&router, "vm1", envelope, "x-ota-commit").await;
    assert_eq!(final_body["phase"], "execute");
    assert_eq!(final_body["status"], "completed");
    assert!(final_body.get("error").is_none());
}

#[tokio::test]
async fn ota_rollback_via_sovd() {
    let (router, _, keys) = make_router();
    let envelope = make_test_suit_envelope(&keys, "vm1", 4, &vec![0xDD; 1024]);
    let final_body = run_spec_cycle(&router, "vm1", envelope, "x-ota-rollback").await;
    assert_eq!(final_body["phase"], "execute");
    assert_eq!(final_body["status"], "failed");
    assert_eq!(
        final_body["error"]["error_code"], "x-ota-verdict-rollback",
        "rollback attribution: {final_body}"
    );
}

// ============================================================
// SUIT provider unit tests
// ============================================================

#[test]
fn suit_provider_validates_good_envelope() {
    let keys = generate_test_keys();
    let provider = SuitProvider::new(keys.trust_anchor.clone());
    // Software authority = same key as signing key (trust anchor) for tests
    provider.update_keys(keys.trust_anchor.clone(), None, None);
    let image = vec![0xDD; 4096];
    let envelope = make_test_suit_envelope(&keys, "vm1", 5, &image);

    let result = provider.validate(&envelope, 0).unwrap();
    assert_eq!(result.bank_set, BankSet::Vm1);
    assert_eq!(result.image_meta.fw_seq, 5);
    assert_eq!(result.image_data, image);
}

#[test]
fn suit_provider_rejects_wrong_key() {
    let keys = generate_test_keys();
    let other_keys = generate_test_keys();
    let provider = SuitProvider::new(other_keys.trust_anchor.clone());
    // Set wrong software authority — should reject firmware
    provider.update_keys(other_keys.trust_anchor.clone(), None, None);
    let image = vec![0xEE; 256];
    let envelope = make_test_suit_envelope(&keys, "vm1", 1, &image);
    assert!(provider.validate(&envelope, 0).is_err());
}

#[test]
fn suit_provider_rejects_rollback() {
    let keys = generate_test_keys();
    let provider = SuitProvider::new(keys.trust_anchor.clone());
    provider.update_keys(keys.trust_anchor.clone(), None, None);
    let image = vec![0xFF; 256];
    let envelope = make_test_suit_envelope(&keys, "vm1", 3, &image);
    assert!(provider.validate(&envelope, 5).is_err());
}

// =============================================================================
// F.D5 — ComponentBackend reports the lifecycle shape used by SOVDd's /campaigns
// =============================================================================

#[tokio::test]
async fn update_shape_reports_banked_for_ab_components() {
    let (_router, _, _) = make_router();
    let keys = generate_test_keys();
    let suit_provider = SuitProvider::new(keys.trust_anchor.clone());
    suit_provider.update_keys(keys.trust_anchor.clone(), None, None);
    let manifest_provider: Arc<dyn ManifestProvider> = Arc::new(suit_provider);
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let nv = Arc::new(Mutex::new(NvStore::new(dev)));

    let banked = ComponentBackend::new(
        BankSet::Vm1,
        nv.clone(),
        manifest_provider.clone(),
        ComponentConfig::default(),
    );
    assert_eq!(
        DiagnosticBackend::update_shape(&banked),
        "banked",
        "VM bank-set with single_bank=false must report banked"
    );

    let singleshot = ComponentBackend::new(
        BankSet::Hsm,
        nv,
        manifest_provider,
        ComponentConfig {
            supports_rollback: false,
            single_bank: true,
            entity_type: "hsm".into(),
            log_sources: Vec::new(),
            test_agent_url: None,
            diag_agent_url: None,
            host_diagnostics: false,
        },
    );
    assert_eq!(
        DiagnosticBackend::update_shape(&singleshot),
        "singleshot",
        "single_bank=true must report singleshot (HSM keystore semantics)"
    );
}

// =============================================================================
// Administrative disable over the real /updates wire
// =============================================================================

/// Recording deactivator — an equipped `Deactivator` is what makes a component
/// disableable, and its call count is the "did the enact actually run?" probe.
struct CountingDeactivator(AtomicUsize);

impl Deactivator for CountingDeactivator {
    fn deactivate(&self) -> Result<DeactivateOutcome, DeactivateError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(DeactivateOutcome {
            reboot_required: false,
        })
    }
}

/// A single-component router wired for administrative disable: a `Deactivator`
/// (so the component is disableable) plus a selector-backed bank provider (so
/// `record_disabled` lands in the shared signed selector the test reads back).
/// `config.single_bank` picks the update shape — banked (vm1) vs singleshot
/// (rt, the field shape). Also hands back the backend, so a test can read the
/// flash transfer state the /updates wire polls.
fn make_disable_router(
    id: &str,
    set: BankSet,
    config: ComponentConfig,
) -> (
    axum::Router,
    TestKeys,
    SharedSystemBankState,
    Arc<CountingDeactivator>,
    Arc<ComponentBackend<MemBlockDevice>>,
) {
    let keys = generate_test_keys();
    let suit_provider = SuitProvider::new(keys.trust_anchor.clone());
    suit_provider.update_keys(keys.trust_anchor.clone(), None, None);
    let manifest_provider: Arc<dyn ManifestProvider> = Arc::new(suit_provider);

    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    let mut boot_state = NvBootState::default();
    nv.write_boot_state(&mut boot_state).unwrap();
    let nv = Arc::new(Mutex::new(nv));

    // Sealed booted selection for the component; the disable set starts empty.
    let selector: SharedSystemBankState = Arc::new(std::sync::RwLock::new(
        SystemBankManager::load(Box::new(InMemorySelectorStore::new()), Box::new(TestSigner)),
    ));
    {
        let mut g = selector.write().unwrap();
        g.stage(set, Bank::A);
        g.seal();
    }

    let single_bank = config.single_bank;
    let deactivator = Arc::new(CountingDeactivator(AtomicUsize::new(0)));
    let backend = Arc::new(
        ComponentBackend::new(set, nv.clone(), manifest_provider, config)
            .with_id(id.to_string())
            .with_bank_provider(Arc::new(IvdBankProvider::new(
                nv,
                set,
                single_bank,
                None,
                id.into(),
                None,
                None,
                Some(selector.clone()),
            )))
            .with_deactivator(deactivator.clone()),
    );

    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    backends.insert(id.to_string(), backend.clone());
    let router = sovd_api::create_router(sovd_api::AppState::new(backends));
    (router, keys, selector, deactivator, backend)
}

/// A REAL signed administrative-disable manifest: one component, no payload
/// digest, `suit-directive-disable` in the shared sequence — the shape the
/// campaign minter emits (151 bytes on the wire).
fn make_disable_envelope(keys: &TestKeys, component: &str, seq: u64) -> Vec<u8> {
    ImageManifestBuilder::new()
        .signing_time(1_700_000_000)
        .component_id(vec![component.to_string()])
        .sequence_number(seq)
        .build_disable(&keys.signing_key)
        .unwrap()
}

/// A detached firmware manifest: declares one payload part (digest + uri) but
/// carries no integrated payload, so the upload must park awaiting that part.
fn make_detached_firmware_envelope(keys: &TestKeys, component: &str, seq: u64) -> Vec<u8> {
    let image = vec![0xAA; 1024];
    let digest = RustCryptoBackend::new().sha256(&image);
    ImageManifestBuilder::new()
        .signing_time(1_700_000_000)
        .component_id(vec![component.to_string(), "firmware".to_string()])
        .sequence_number(seq)
        .payload_digest(&digest, image.len() as u64)
        .payload_uri("#firmware".to_string())
        .build(&keys.signing_key)
        .unwrap()
}

/// Register an update and upload `envelope` as the `manifest` part.
async fn register_and_upload_manifest(
    router: &axum::Router,
    component: &str,
    envelope: Vec<u8>,
) -> String {
    let (status, body) = post_json(
        router,
        &format!("/vehicle/v1/components/{component}/updates"),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "register_update: {body}");
    let update_id = body["update_id"].as_str().unwrap().to_string();

    let (status, _) = put_bytes(
        router,
        &format!("/vehicle/v1/components/{component}/updates/{update_id}/bulk-data/manifest"),
        envelope,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    update_id
}

#[tokio::test]
async fn disable_manifest_settles_prepare_and_enacts_at_execute() {
    // Field failure (S32G3 bench): the 151-byte signed disable manifest uploaded
    // fine, then PUT /prepare burned SOVDd's whole 30 s `await_flash_settled`
    // window and returned GatewayTimeout. The manifest declares NO payload part,
    // so nothing would ever arrive to move `flash_transfer.state` off
    // Transferring. Drives the real router end to end: upload → prepare (must
    // settle at once) → execute (must enact the disable).
    let (router, keys, selector, deact, backend) =
        make_disable_router("vm1", BankSet::Vm1, ComponentConfig::default());
    assert!(
        !selector.read().unwrap().disabled(BankSet::Vm1),
        "starts enabled"
    );

    let update_id =
        register_and_upload_manifest(&router, "vm1", make_disable_envelope(&keys, "vm1", 5)).await;

    // Prepare must settle immediately — nothing to transfer. The elapsed bound
    // IS the regression: pre-fix this sat in `await_flash_settled` for 30 s.
    let started = std::time::Instant::now();
    let (status, _) = put_empty(
        &router,
        &format!("/vehicle/v1/components/vm1/updates/{update_id}/prepare"),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let prepared = poll_status_until_terminal(&router, "vm1", &update_id).await;
    assert_eq!(prepared["phase"], "prepare", "prepare: {prepared}");
    assert_eq!(prepared["status"], "completed", "prepare: {prepared}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "prepare took {:?} — a payload-less manifest must not wait on a transfer",
        started.elapsed(),
    );

    // Execute enacts: deactivate + record_disabled(true) in the signed selector.
    // The banked follow-on validate/activate are no-ops on the already-Activated
    // transfer a disable parks, so the wire reports a clean execute/completed.
    let (status, _) = put_empty(
        &router,
        &format!("/vehicle/v1/components/vm1/updates/{update_id}/execute"),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let executed = poll_status_until_terminal(&router, "vm1", &update_id).await;
    assert_eq!(executed["phase"], "execute", "execute: {executed}");
    assert_eq!(executed["status"], "completed", "execute: {executed}");

    assert_eq!(
        deact.0.load(Ordering::SeqCst),
        1,
        "deactivate() ran exactly once, at execute"
    );
    assert!(
        selector.read().unwrap().disabled(BankSet::Vm1),
        "record_disabled(true) persisted in the signed selector"
    );
    // A disable stages no bank content, so it must never open a trial: the bank
    // set stays committed and the component therefore enters NEITHER the
    // `x-ota-update-state` Trial set nor the node flash gate's live-trial set.
    let bank = backend.nv_lock().unwrap().read_boot_state().unwrap().banks[BankSet::Vm1.as_index()]
        .clone();
    assert!(
        bank.committed,
        "a disable owes no verdict — it must not put the bank set in trial: {bank:?}"
    );
    // And it is visible on the wire the operator reads.
    let (status, body) = get(&router, "/vehicle/v1/components/vm1/status").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["x-runtime"]["admin_state"], "disabled",
        "entity status read-back: {body}"
    );
}

#[tokio::test]
async fn firmware_manifest_still_awaits_its_payload() {
    // Counter-assertion to the settle above: a manifest that DOES declare a
    // payload part keeps parking — the transfer stays Transferring until the
    // part arrives, so `await_flash_settled` still means "the payload landed".
    let (router, keys, _selector, _deact, backend) =
        make_disable_router("vm1", BankSet::Vm1, ComponentConfig::default());

    let _update_id = register_and_upload_manifest(
        &router,
        "vm1",
        make_detached_firmware_envelope(&keys, "vm1", 6),
    )
    .await;

    let flash = backend.get_flash_status("").await.unwrap();
    assert_eq!(
        flash.state,
        FlashState::Transferring,
        "a manifest declaring a payload part must stay Transferring until it arrives"
    );
}

#[tokio::test]
async fn singleshot_disable_settles_prepare_and_enacts_at_execute() {
    // The FIELD shape: `rt` is single-bank, so `update_shape` is "singleshot"
    // and the execute wire drives finalize → commit_flash, never
    // validate/activate. Same contract as the banked case — prepare settles at
    // once, execute enacts and terminates clean.
    let (router, keys, selector, deact, backend) = make_disable_router(
        "rt",
        BankSet::Rt,
        ComponentConfig {
            supports_rollback: false,
            single_bank: true,
            entity_type: "rt".into(),
            ..ComponentConfig::default()
        },
    );
    assert_eq!(
        DiagnosticBackend::update_shape(backend.as_ref()),
        "singleshot",
        "fixture must reproduce the field component's shape"
    );

    let update_id =
        register_and_upload_manifest(&router, "rt", make_disable_envelope(&keys, "rt", 5)).await;

    let started = std::time::Instant::now();
    let (status, _) = put_empty(
        &router,
        &format!("/vehicle/v1/components/rt/updates/{update_id}/prepare"),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let prepared = poll_status_until_terminal(&router, "rt", &update_id).await;
    assert_eq!(prepared["status"], "completed", "prepare: {prepared}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "prepare took {:?} — a payload-less manifest must not wait on a transfer",
        started.elapsed(),
    );

    let (status, _) = put_empty(
        &router,
        &format!("/vehicle/v1/components/rt/updates/{update_id}/execute"),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let executed = poll_status_until_terminal(&router, "rt", &update_id).await;
    assert_eq!(executed["phase"], "execute", "execute: {executed}");
    assert_eq!(executed["status"], "completed", "execute: {executed}");

    assert_eq!(
        deact.0.load(Ordering::SeqCst),
        1,
        "deactivate() ran exactly once, at execute"
    );
    assert!(
        selector.read().unwrap().disabled(BankSet::Rt),
        "record_disabled(true) persisted in the signed selector"
    );
}

// =============================================================================
// Node update-transaction gate over the real wire — ONE banked campaign step
// ["vm1","vm2"]: flash both, ONE activation reboot, ONE commit-trials
// =============================================================================

/// vm1 + vm2 sharing ONE node update coordinator (the gate every deployment
/// binary wires) plus the node-level verdict routes. Mirrors `vm-sovd`'s
/// wiring: the same backends serve the SOVD component routes and, through
/// `ComponentAdapter`, the `Machine` the node verdict fans out over. Hands back
/// the NV store so a test can read the armed / live-trial facts the gate
/// decides on.
fn make_node_router() -> (axum::Router, Arc<Mutex<NvStore<MemBlockDevice>>>, TestKeys) {
    let keys = generate_test_keys();
    let suit_provider = SuitProvider::new(keys.trust_anchor.clone());
    suit_provider.update_keys(keys.trust_anchor.clone(), None, None);
    let manifest_provider: Arc<dyn ManifestProvider> = Arc::new(suit_provider);

    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot_state = NvBootState::default();
    nv.write_boot_state(&mut boot_state).unwrap();
    let nv = Arc::new(Mutex::new(nv));

    let coord = Arc::new(NodeCoordinator::new(vec![
        (BankSet::Vm1.as_index(), "vm1".to_string()),
        (BankSet::Vm2.as_index(), "vm2".to_string()),
    ]));

    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    let mut machine = MachineRegistry::builder(EntityInfo {
        id: "vehicle".into(),
        name: "vehicle".into(),
        entity_type: "vehicle".into(),
        description: None,
        href: "/vehicle/v1".into(),
        status: None,
    });
    for (id, set) in [("vm1", BankSet::Vm1), ("vm2", BankSet::Vm2)] {
        let backend = Arc::new(
            ComponentBackend::new(
                set,
                nv.clone(),
                manifest_provider.clone(),
                ComponentConfig::default(),
            )
            .with_id(id.to_string())
            .with_node_coordinator(coord.clone()),
        );
        backends.insert(id.to_string(), backend.clone());
        machine = machine.with(ComponentAdapter::new(backend));
    }

    let router = sovd_api::create_router(sovd_api::AppState::new(backends)).merge(
        component_mgr::sovd::routes::node_verdict_router(
            Arc::new(machine.build()),
            nv.clone(),
            coord,
        ),
    );
    (router, nv, keys)
}

/// The bank-set boot state the node gate reads (active bank, committed,
/// boot_count).
fn bank_state(nv: &Arc<Mutex<NvStore<MemBlockDevice>>>, set: BankSet) -> BankBootState {
    nv.lock().unwrap().read_boot_state().unwrap().banks[set.as_index()].clone()
}

/// The coalesced activation reboot for one component, over the real §7.19
/// restart route — the orchestrator's reset step. Switches the running bank to
/// the armed bank and raises the trial `boot_count`.
async fn activation_reset(router: &axum::Router, component: &str) {
    let (status, body) = put_json(
        router,
        &format!("/vehicle/v1/components/{component}/status/restart"),
        serde_json::json!({ "reset_type": "hard" }),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "restart {component}: {body}");
}

#[tokio::test]
async fn armed_pre_reboot_component_does_not_block_a_sibling_open() {
    // FIELD REPRO (S32G3, one banked campaign step ["vm1","vm2"]): vm1 staged and
    // executed to awaiting-verdict — armed, but the coalesced activation reboot
    // has NOT run — and vm2's open_update came back 409 "node owes a verdict for
    // in-trial [\"vm1\"]". That broke the engine's designed one-trial-step
    // coalescing (flash all banked -> ONE reboot -> trial all -> ONE
    // commit-trials). vm1 owes no verdict yet, so vm2 must be admitted.
    let (router, nv, keys) = make_node_router();

    flash_to_awaiting_verdict(
        &router,
        "vm1",
        make_test_suit_envelope(&keys, "vm1", 2, &vec![0xBB; 2048]),
    )
    .await;

    // The armed-pre-reboot fact the gate must distinguish: trial content staged
    // (uncommitted) but never booted into (`boot_count == 0`).
    let vm1_bank = bank_state(&nv, BankSet::Vm1);
    assert!(!vm1_bank.committed, "vm1 is armed: {vm1_bank:?}");
    assert_eq!(
        vm1_bank.boot_count, 0,
        "…and has NOT taken the activation reboot: {vm1_bank:?}"
    );

    let (status, body) = post_json(
        &router,
        "/vehicle/v1/components/vm2/updates",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "vm2 must join the campaign step while vm1 is armed-pre-reboot: {body}"
    );
}

#[tokio::test]
async fn live_trial_still_refuses_a_new_flash() {
    // The gate's genuine case, unchanged: once the activation reboot HAS happened
    // (running == armed, still uncommitted) the node owes a verdict, and a new
    // flash is refused 409 with the owes-a-verdict message — the engine's
    // state-gated recovery keys off exactly this refusal.
    let (router, nv, keys) = make_node_router();

    flash_to_awaiting_verdict(
        &router,
        "vm1",
        make_test_suit_envelope(&keys, "vm1", 2, &vec![0xBB; 2048]),
    )
    .await;
    activation_reset(&router, "vm1").await;

    let vm1_bank = bank_state(&nv, BankSet::Vm1);
    assert!(
        !vm1_bank.committed,
        "vm1 still owes a verdict: {vm1_bank:?}"
    );
    assert!(
        vm1_bank.boot_count > 0,
        "…and its trial is now LIVE — it booted the armed bank: {vm1_bank:?}"
    );

    let (status, body) = post_json(
        &router,
        "/vehicle/v1/components/vm2/updates",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "open_update: {body}");
    let msg = body["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("owes a verdict for in-trial") && msg.contains("vm1"),
        "expected the node-gate Trial refusal naming vm1, got: {body}"
    );
}

#[tokio::test]
async fn commit_trials_resolves_both_components_after_one_coalesced_reboot() {
    // The whole banked step end to end: flash BOTH components (the sibling open
    // that used to 409), take ONE activation reboot, then ONE node commit-trials
    // resolves the pair — the multi-component node verdict the engine issues.
    let (router, nv, keys) = make_node_router();

    flash_to_awaiting_verdict(
        &router,
        "vm1",
        make_test_suit_envelope(&keys, "vm1", 2, &vec![0xBB; 2048]),
    )
    .await;
    flash_to_awaiting_verdict(
        &router,
        "vm2",
        make_test_suit_envelope(&keys, "vm2", 2, &vec![0xCC; 2048]),
    )
    .await;

    for component in ["vm1", "vm2"] {
        activation_reset(&router, component).await;
    }

    let (status, body) = post_json(
        &router,
        "/vehicle/v1/operations/x-ota-commit-trials/executions",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "commit-trials: {body}");
    let committed = body["result"]["committed"].as_array().unwrap();
    assert!(
        committed.contains(&serde_json::json!("vm1"))
            && committed.contains(&serde_json::json!("vm2")),
        "one node verdict must resolve the whole step: {body}"
    );

    for set in [BankSet::Vm1, BankSet::Vm2] {
        let bank = bank_state(&nv, set);
        assert!(bank.committed, "{set:?} committed in NV: {bank:?}");
    }
}
