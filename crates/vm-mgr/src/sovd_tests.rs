/// Integration tests for VmBackend via sovd-api.
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

use crate::backend::{ComponentConfig, VmBackend};
use crate::manifest_provider::ManifestProvider;
use crate::ota;
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
        .component_id(vec![component.to_string()])
        .sequence_number(seq)
        .payload_digest(&digest, image.len() as u64)
        .payload_uri("#firmware".to_string())
        .integrated_payload("#firmware".to_string(), image.to_vec())
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
            BankSet::HostOs,
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
            Arc::new(VmBackend::new(
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

async fn post_bytes(
    router: &axum::Router,
    uri: &str,
    data: Vec<u8>,
) -> (StatusCode, serde_json::Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::post(uri)
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

async fn post_empty(router: &axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let resp = router
        .clone()
        .oneshot(Request::post(uri).body(Body::empty()).unwrap())
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
    assert!(items.len() >= 21);
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
// Flash gating
// ============================================================

#[tokio::test]
async fn flash_rejected_in_default_session() {
    let (router, _, keys) = make_router();
    let envelope = make_test_suit_envelope(&keys, "vm1", 1, &[0xAA; 256]);
    let (status, _) = post_bytes(&router, "/vehicle/v1/components/vm1/files", envelope).await;
    // Should be rejected — not in programming session
    assert_ne!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn flash_rejected_when_locked() {
    let (router, _, keys) = make_router();
    // Programming but no security unlock
    put_json(
        &router,
        "/vehicle/v1/components/vm1/modes/session",
        serde_json::json!({"value": "programming"}),
    )
    .await;

    let envelope = make_test_suit_envelope(&keys, "vm1", 1, &[0xAA; 256]);
    let (status, _) = post_bytes(&router, "/vehicle/v1/components/vm1/files", envelope).await;
    assert_ne!(status, StatusCode::CREATED);
}

// ============================================================
// Flash full flow
// ============================================================

#[tokio::test]
async fn flash_full_suit_flow() {
    let (router, _, keys) = make_router();
    unlock_for_flash(&router, "vm1").await;

    let image = vec![0xBB; 2048];
    let envelope = make_test_suit_envelope(&keys, "vm1", 2, &image);

    // 1. Upload
    let (status, json) = post_bytes(&router, "/vehicle/v1/components/vm1/files", envelope).await;
    assert_eq!(status, StatusCode::CREATED);
    let file_id = json["file_id"].as_str().unwrap().to_string();

    // 2. Verify
    let (status, json) = post_empty(
        &router,
        &format!("/vehicle/v1/components/vm1/files/{file_id}/verify"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["valid"].as_bool().unwrap());

    // 3. Start transfer
    let (status, _json) = post_json(
        &router,
        "/vehicle/v1/components/vm1/flash/transfer",
        serde_json::json!({"file_id": file_id}),
    )
    .await;
    assert!(status == StatusCode::OK || status == StatusCode::ACCEPTED);

    // 4. Check activation — should be trial (activated)
    let (status, json) = get(&router, "/vehicle/v1/components/vm1/flash/activation").await;
    assert_eq!(status, StatusCode::OK);
    // Trial state — sovd-api serializes FlashState::Activated
    assert!(json["state"].as_str().unwrap() != "committed");

    // 5. Commit
    let (status, _) = post_empty(&router, "/vehicle/v1/components/vm1/flash/commit").await;
    assert_eq!(status, StatusCode::OK);

    // 6. Verify idle after commit. start_flash clears the packages map, so
    // this contrived flow never reaches install(); fw_meta stays empty on
    // both banks → "initial" (never-OTA'd) is the truthful end state.
    let (status, json) = get(&router, "/vehicle/v1/components/vm1/flash/activation").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["state"], "initial");
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

#[tokio::test]
async fn ota_commit_via_sovd() {
    let (router, nv, _) = make_router();

    // Install OTA directly via library
    {
        let mut nv = nv.lock().unwrap();
        let mut meta = ota::ImageMeta::default();
        meta.fw_version[..5].copy_from_slice(b"2.0.0");
        meta.fw_secver = 1;
        meta.fw_seq = 1;
        ota::install(&mut *nv, BankSet::Vm1, b"test", &meta, false).unwrap();
    }

    let (_, json) = get(&router, "/vehicle/v1/components/vm1/flash/activation").await;
    // Trial state — sovd-api serializes FlashState::Activated
    assert!(json["state"].as_str().unwrap() != "committed");

    let (status, _) = post_empty(&router, "/vehicle/v1/components/vm1/flash/commit").await;
    assert_eq!(status, StatusCode::OK);

    let (_, json) = get(&router, "/vehicle/v1/components/vm1/flash/activation").await;
    assert_eq!(json["state"], "complete"); // idle after commit
}

#[tokio::test]
async fn ota_rollback_via_sovd() {
    let (router, nv, _) = make_router();

    {
        let mut nv = nv.lock().unwrap();
        let mut meta = ota::ImageMeta::default();
        meta.fw_version[..5].copy_from_slice(b"2.0.0");
        meta.fw_secver = 1;
        meta.fw_seq = 1;
        ota::install(&mut *nv, BankSet::Vm1, b"test", &meta, false).unwrap();
    }

    let (status, _) = post_empty(&router, "/vehicle/v1/components/vm1/flash/rollback").await;
    assert_eq!(status, StatusCode::OK);

    let (_, json) = get(&router, "/vehicle/v1/components/vm1/data/active_bank").await;
    assert_eq!(json["value"], "A");
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
