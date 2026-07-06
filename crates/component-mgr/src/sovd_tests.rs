/// Integration tests for ComponentBackend via sovd-api.
///
/// These test the full HTTP flow through sovd-api's router, ensuring
/// our DiagnosticBackend implementation works correctly with the
/// standard SOVD REST API.
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

use crate::backend::{ComponentBackend, ComponentConfig};
use crate::manifest_provider::ManifestProvider;
use crate::sovd::security::TestSecurityProvider;
use crate::suit_provider::SuitProvider;

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
    let security_provider = Arc::new(TestSecurityProvider);

    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    let mut boot_state = NvBootState::default();
    nv.write_boot_state(&mut boot_state).unwrap();
    let nv = Arc::new(Mutex::new(nv));

    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    let components: Vec<(&str, BankSet, ComponentConfig)> = vec![
        (
            "host-os",
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
            },
        ),
    ];
    for (id, set, config) in components {
        backends.insert(
            id.to_string(),
            Arc::new(ComponentBackend::new(
                set,
                nv.clone(),
                manifest_provider.clone(),
                security_provider.clone(),
                config,
            )),
        );
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
        if body["x-sumo-substate"].as_str() == Some("awaiting-verdict")
            || matches!(body["status"].as_str(), Some("completed") | Some("failed"))
        {
            return body;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("status never reached awaiting-verdict")
}

/// Unlock a component: switch to programming + seed/key flow.
async fn unlock_for_flash(router: &axum::Router, component: &str) {
    put_json(
        router,
        &format!("/vehicle/v1/components/{component}/modes/session"),
        serde_json::json!({"value": "programming"}),
    )
    .await;

    let (_, seed_resp) = put_json(
        router,
        &format!("/vehicle/v1/components/{component}/modes/security"),
        serde_json::json!({"value": "level1_requestseed"}),
    )
    .await;

    // Seed is a concatenated lowercase hex string per ISO 17978-3
    // `string:hex` primitive (sovd_iso17978_spec.yaml line 192).
    let seed_str = seed_resp["seed"].as_str().unwrap();
    let seed_bytes = hex::decode(seed_str).unwrap();
    let key_hex: String = seed_bytes
        .iter()
        .map(|b| format!("{:02x}", b ^ 0xFF))
        .collect();

    put_json(
        router,
        &format!("/vehicle/v1/components/{component}/modes/security"),
        serde_json::json!({"value": "level1", "key": key_hex}),
    )
    .await;
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
    assert!(json["capabilities"]["sessions"].as_bool().unwrap());
    assert!(json["capabilities"]["security"].as_bool().unwrap());
    assert!(json["capabilities"]["software_update"].as_bool().unwrap());
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
// Session / Security
// ============================================================

#[tokio::test]
async fn session_default_initially() {
    let (router, _, _) = make_router();
    let (status, json) = get(&router, "/vehicle/v1/components/vm1/modes/session").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["value"], "default");
}

#[tokio::test]
async fn session_switch_to_programming() {
    let (router, _, _) = make_router();
    let (status, json) = put_json(
        &router,
        "/vehicle/v1/components/vm1/modes/session",
        serde_json::json!({"value": "programming"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["value"], "programming");
}

#[tokio::test]
async fn security_locked_initially() {
    let (router, _, _) = make_router();
    let (status, json) = get(&router, "/vehicle/v1/components/vm1/modes/security").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["value"], "locked");
}

#[tokio::test]
async fn security_seed_key_unlock() {
    let (router, _, _) = make_router();
    // Programming session first
    put_json(
        &router,
        "/vehicle/v1/components/vm1/modes/session",
        serde_json::json!({"value": "programming"}),
    )
    .await;

    // Request seed
    let (status, json) = put_json(
        &router,
        "/vehicle/v1/components/vm1/modes/security",
        serde_json::json!({"value": "level1_requestseed"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Seed is a concatenated lowercase hex string per ISO 17978-3
    // `string:hex` primitive (sovd_iso17978_spec.yaml line 192).
    assert!(json["seed"].is_string());
    let seed_str = json["seed"].as_str().unwrap();
    let seed_bytes = hex::decode(seed_str).unwrap();
    let key_hex: String = seed_bytes
        .iter()
        .map(|b| format!("{:02x}", b ^ 0xFF))
        .collect();

    // Send key
    let (status, json) = put_json(
        &router,
        "/vehicle/v1/components/vm1/modes/security",
        serde_json::json!({"value": "level1", "key": key_hex}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Unlocked — value should be "level1"
    assert!(json["value"].as_str().unwrap().contains("level"));
}

#[tokio::test]
async fn session_change_resets_security() {
    let (router, _, _) = make_router();
    unlock_for_flash(&router, "vm1").await;

    // Switch back to default
    put_json(
        &router,
        "/vehicle/v1/components/vm1/modes/session",
        serde_json::json!({"value": "default"}),
    )
    .await;

    // Security should be locked
    let (_, json) = get(&router, "/vehicle/v1/components/vm1/modes/security").await;
    assert_eq!(json["value"], "locked");
}

// ============================================================
// Flash authorization (native SOVD: bearer token, not a UDS session)
// ============================================================

#[tokio::test]
async fn flash_accepted_without_uds_session() {
    // The host is a native SOVD server: privileged /updates is authorized by
    // the bearer token (ISO 17978-3 §5.4.4), NOT a UDS programming session. With
    // the legacy UDS session/security gate dropped (and auth not yet enforced), a
    // flash in the default, locked session is accepted — no programming/unlock
    // dance. This is the path rig + provision drive.
    let (router, _, keys) = make_router();
    // Deliberately NO unlock_for_flash — default session, security locked.

    let image = vec![0xBB; 2048];
    let envelope = make_test_suit_envelope(&keys, "vm1", 2, &image);

    // POST /updates calls backend.start_flash (require_flash_access) — previously
    // rejected 409 "Session change required: programming" without a session.
    let (status, body) = post_json(
        &router,
        "/vehicle/v1/components/vm1/updates",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "register_update without unlock: {body}"
    );
    let update_id = body["update_id"].as_str().unwrap().to_string();

    // PUT /bulk-data/manifest — the exact upload that hit the 409 gate in the
    // provision flow; now accepted unauthenticated (server warns).
    let (status, _) = put_bytes(
        &router,
        &format!("/vehicle/v1/components/vm1/updates/{update_id}/bulk-data/manifest"),
        envelope,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "manifest upload without unlock"
    );
}

// ============================================================
// Flash full flow
// ============================================================

#[tokio::test]
async fn flash_full_suit_flow() {
    // Spec-wire round trip — register the update, upload the SUIT
    // envelope as the `manifest` part, drive prepare + execute(orchestrated),
    // then commit via the Phase B vendor verb.  Asserts every transition.
    let (router, _, keys) = make_router();
    unlock_for_flash(&router, "vm1").await;

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

    // 4. PUT /execute?x-sumo-control=orchestrated — banked ComponentBackend
    //    runs finalize+validate+activate then pauses at
    //    substate=awaiting-verdict.
    let (status, _) = put_empty(
        &router,
        &format!(
            "/vehicle/v1/components/vm1/updates/{update_id}/execute?x-sumo-control=orchestrated"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let paused = poll_status_until_awaiting_verdict(&router, "vm1", &update_id).await;
    assert_eq!(paused["phase"], "execute");
    assert_eq!(paused["status"], "inProgress");
    assert_eq!(paused["x-sumo-substate"], "awaiting-verdict");

    // 5. PUT /x-sumo-commit — Phase B vendor verb.  Wakes the paused
    //    execute task; calls backend.commit_flash; transitions to
    //    execute/completed.
    let (status, _) = put_empty(
        &router,
        &format!("/vehicle/v1/components/vm1/updates/{update_id}/x-sumo-commit"),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let final_body = poll_status_until_terminal(&router, "vm1", &update_id).await;
    assert_eq!(final_body["phase"], "execute");
    assert_eq!(final_body["status"], "completed");
    assert!(final_body.get("x-sumo-substate").is_none());
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
    unlock_for_flash(&router, "vm1").await;

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

/// Drive a full prepare+execute+verdict cycle and return the
/// post-verdict `UpdateStatusBody`.  `verdict_verb` is one of
/// `x-sumo-commit` / `x-sumo-rollback`.
async fn run_spec_cycle(
    router: &axum::Router,
    component: &str,
    envelope: Vec<u8>,
    verdict_verb: &str,
) -> serde_json::Value {
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
             /execute?x-sumo-control=orchestrated"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    poll_status_until_awaiting_verdict(router, component, &update_id).await;

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
    unlock_for_flash(&router, "vm1").await;
    let envelope = make_test_suit_envelope(&keys, "vm1", 3, &vec![0xCC; 1024]);
    let final_body = run_spec_cycle(&router, "vm1", envelope, "x-sumo-commit").await;
    assert_eq!(final_body["phase"], "execute");
    assert_eq!(final_body["status"], "completed");
    assert!(final_body.get("error").is_none());
}

#[tokio::test]
async fn ota_rollback_via_sovd() {
    let (router, _, keys) = make_router();
    unlock_for_flash(&router, "vm1").await;
    let envelope = make_test_suit_envelope(&keys, "vm1", 4, &vec![0xDD; 1024]);
    let final_body = run_spec_cycle(&router, "vm1", envelope, "x-sumo-rollback").await;
    assert_eq!(final_body["phase"], "execute");
    assert_eq!(final_body["status"], "failed");
    assert_eq!(
        final_body["error"]["error_code"], "x-sumo-verdict-rollback",
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
    let security_provider = Arc::new(TestSecurityProvider);
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let nv = Arc::new(Mutex::new(NvStore::new(dev)));

    let banked = ComponentBackend::new(
        BankSet::Vm1,
        nv.clone(),
        manifest_provider.clone(),
        security_provider.clone(),
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
        security_provider,
        ComponentConfig {
            supports_rollback: false,
            single_bank: true,
            entity_type: "hsm".into(),
        },
    );
    assert_eq!(
        DiagnosticBackend::update_shape(&singleshot),
        "singleshot",
        "single_bank=true must report singleshot (HSM keystore semantics)"
    );
}
