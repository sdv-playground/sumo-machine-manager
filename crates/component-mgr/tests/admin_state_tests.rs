//! Integration tests for the per-component administrative state slice:
//! `ComponentBackend::set_admin_state` semantics (persist-first, idle-only
//! admission, idempotency), the flash-gate + status + reset enforcement
//! points, and the `x-sumo-admin-state` vendor router (auth, wire codes,
//! §7.14 execution body) through the public API — mirroring the
//! `sovd_tests.rs` harness style.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use nv_store::block::MemBlockDevice;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::*;

use machine_mgr::{
    DeactivateError, DeactivateOutcome, Deactivator, EntityInfo, Machine, MachineRegistry,
};
use sovd_core::{DiagnosticBackend, EntityStatus};

use component_mgr::backend::{ComponentBackend, ComponentConfig};
use component_mgr::component_adapter::ComponentAdapter;
use component_mgr::manifest_provider::{ManifestError, ManifestProvider, ValidatedFirmware};
use component_mgr::sovd::admin_state::{admin_state_router, ADMIN_STATE_OP_ID};
use component_mgr::sovd::authz::{Tier, TieredAuthorizer, TrustedIssuer};

// --- Harness ---------------------------------------------------------------

/// Manifest validation is never reached by the admin-state paths — a stub
/// keeps the harness free of the SUIT/key machinery.
struct StubManifests;
impl ManifestProvider for StubManifests {
    fn validate(&self, _data: &[u8], _min: u32) -> Result<ValidatedFirmware, ManifestError> {
        Err(ManifestError::ParseError("stub".into()))
    }
}

/// Recording deactivator: counts calls; configurable outcome.
struct MockDeactivator {
    calls: AtomicUsize,
    fail: bool,
    reboot_required: bool,
}

impl MockDeactivator {
    fn ok() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            fail: false,
            reboot_required: false,
        }
    }
    fn failing() -> Self {
        Self {
            fail: true,
            ..Self::ok()
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Deactivator for MockDeactivator {
    fn deactivate(&self) -> Result<DeactivateOutcome, DeactivateError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            Err(DeactivateError::Failed("mock enact failure".into()))
        } else {
            Ok(DeactivateOutcome {
                reboot_required: self.reboot_required,
            })
        }
    }
}

/// Probe-backed component (rt-style): configurable readiness + fixed
/// runtime extensions, including a deliberate standard-field collision.
struct MockProbe {
    running: bool,
}

impl component_mgr::backend::HealthProbe for MockProbe {
    fn probe(&self) -> Option<component_mgr::backend::GuestHealth> {
        self.running.then(|| component_mgr::backend::GuestHealth {
            guest_state: 1,
            hb_seq: 7,
            boot_id: 42,
            status: "running".into(),
        })
    }
    fn runtime_extensions(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut m = serde_json::Map::new();
        m.insert("m7_total_startup".into(), serde_json::json!(86));
        // Collision: standard fields must win over probe contributions.
        m.insert("boot_count".into(), serde_json::json!(999));
        m
    }
}

type SharedNv = Arc<Mutex<NvStore<MemBlockDevice>>>;

fn make_nv() -> SharedNv {
    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    nv.write_boot_state(&mut boot).unwrap();
    Arc::new(Mutex::new(nv))
}

fn vm_backend(
    nv: &SharedNv,
    set: BankSet,
    vm_service_addr: Option<String>,
) -> ComponentBackend<MemBlockDevice> {
    ComponentBackend::with_options(
        set,
        nv.clone(),
        Arc::new(StubManifests),
        ComponentConfig::default(),
        vm_service_addr,
        None,
        None,
    )
}

fn hsm_backend(nv: &SharedNv) -> ComponentBackend<MemBlockDevice> {
    ComponentBackend::with_options(
        BankSet::Hsm,
        nv.clone(),
        Arc::new(StubManifests),
        ComponentConfig {
            supports_rollback: false,
            single_bank: true,
            entity_type: "hsm".into(),
            log_sources: Vec::new(),
            test_agent_url: None,
            diag_agent_url: None,
            host_diagnostics: false,
        },
        None,
        None,
        None,
    )
}

/// Write the raw NV admin flag directly (the state another path persisted).
fn set_flag(nv: &SharedNv, set: BankSet, disabled: bool) {
    let mut nv = nv.lock().unwrap();
    let mut st = nv.read_admin_state();
    st.set_disabled(set, disabled);
    nv.write_admin_state(&mut st).unwrap();
}

fn flag_of(nv: &SharedNv, set: BankSet) -> bool {
    nv.lock().unwrap().read_admin_state().is_disabled(set)
}

/// Serve canned `200 OK`s on an ephemeral loopback port, counting accepted
/// connections — the observable for "did anything talk to vm-service?".
async fn counting_server() -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            c.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            });
        }
    });
    (addr, count)
}

/// A loopback port with nothing listening (bind-then-drop).
fn dead_addr() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    format!("127.0.0.1:{}", l.local_addr().unwrap().port())
}

// --- Backend semantics -----------------------------------------------------

#[tokio::test]
async fn disable_persists_flag_enacts_once_and_is_idempotent() {
    let nv = make_nv();
    let deact = Arc::new(MockDeactivator::ok());
    let b = vm_backend(&nv, BankSet::Vm1, None).with_deactivator(deact.clone());

    assert!(b.is_disableable());
    assert!(!b.admin_disabled());

    let out = b.set_admin_state(true).await.expect("disable admitted");
    assert!(out.disabled);
    assert!(!out.reboot_required);
    assert!(out.enact_error.is_none());
    // Flag persisted in NV, deactivator enacted exactly once.
    assert!(flag_of(&nv, BankSet::Vm1), "flag must persist in NV");
    assert!(b.admin_disabled());
    assert_eq!(deact.calls(), 1);

    // Idempotent repeat: no-op success, NO second enact.
    let out = b.set_admin_state(true).await.expect("no-op disable");
    assert!(out.disabled);
    assert!(out.enact_error.is_none());
    assert_eq!(deact.calls(), 1, "a no-op repeat must not re-enact");
}

#[tokio::test]
async fn disable_refused_while_node_reboot_owed() {
    // The durable reboot-owed record marks this component as owing the node
    // transaction its activation reboot — disable is not idle then.
    let nv = make_nv();
    {
        let mut nv = nv.lock().unwrap();
        let mut s = NvUpdateSession {
            reboot_owed: 1 << BankSet::Vm1.as_index(),
            ..Default::default()
        };
        nv.write_update_session(&mut s).unwrap();
    }
    let b = vm_backend(&nv, BankSet::Vm1, None).with_deactivator(Arc::new(MockDeactivator::ok()));
    let err = b
        .set_admin_state(true)
        .await
        .expect_err("owing the node reboot must refuse disable");
    assert!(
        err.to_string().contains("pending activation reboot"),
        "wrong refusal: {err}"
    );
    assert!(!flag_of(&nv, BankSet::Vm1), "no flag on a refused disable");
}

#[tokio::test]
async fn enable_clears_flag_and_reports_best_effort_start_failure() {
    // vm-service is unreachable: the enable still succeeds (flag cleared —
    // that IS the state change), and the failed best-effort start is
    // reported honestly as the enact error.
    let nv = make_nv();
    let b = vm_backend(&nv, BankSet::Vm1, Some(dead_addr()))
        .with_deactivator(Arc::new(MockDeactivator::ok()));
    set_flag(&nv, BankSet::Vm1, true);
    assert!(b.admin_disabled());

    let out = b.set_admin_state(false).await.expect("enable succeeds");
    assert!(!out.disabled);
    assert!(!out.reboot_required);
    assert!(
        out.enact_error
            .as_deref()
            .is_some_and(|e| e.contains("vm-service start")),
        "the failed best-effort start must be reported: {:?}",
        out.enact_error
    );
    assert!(!flag_of(&nv, BankSet::Vm1), "flag must be cleared in NV");
}

#[tokio::test]
async fn enact_failure_keeps_disabled_and_reports() {
    // Persist-first ordering: the deactivator failing does NOT roll the flag
    // back — the start gate keeps the component down and the error rides in
    // the outcome.
    let nv = make_nv();
    let deact = Arc::new(MockDeactivator::failing());
    let b = vm_backend(&nv, BankSet::Vm1, None).with_deactivator(deact.clone());

    let out = b
        .set_admin_state(true)
        .await
        .expect("state change succeeds");
    assert!(out.disabled);
    assert!(
        out.enact_error
            .as_deref()
            .is_some_and(|e| e.contains("mock enact failure")),
        "enact error must surface: {:?}",
        out.enact_error
    );
    assert!(flag_of(&nv, BankSet::Vm1), "flag stays persisted");
    assert!(b.admin_disabled());
    assert_eq!(deact.calls(), 1);
}

#[tokio::test]
async fn non_disableable_component_answers_not_supported() {
    let nv = make_nv();
    let b = hsm_backend(&nv);
    assert!(!b.is_disableable());

    let err = b
        .set_admin_state(true)
        .await
        .expect_err("no deactivator = cannot be disabled");
    assert!(
        err.to_string()
            .contains("does not support administrative disable"),
        "{err}"
    );

    // A stale NV bit on a non-disableable slot reads as enabled — the
    // equipped deactivator is the authority.
    set_flag(&nv, BankSet::Hsm, true);
    assert!(!b.admin_disabled());

    // No admin_state field in /status (tri-state read-back), no advertised op.
    let status = b.read_entity_status().await.unwrap();
    let runtime = &status.extensions["x-sumo-runtime"];
    assert!(
        runtime.get("admin_state").is_none(),
        "non-disableable components must omit admin_state entirely"
    );
    assert!(b.list_operations().await.unwrap().is_empty());
}

#[tokio::test]
async fn ensure_flash_can_start_refuses_disabled() {
    let nv = make_nv();
    let b = vm_backend(&nv, BankSet::Vm1, None).with_deactivator(Arc::new(MockDeactivator::ok()));
    b.ensure_flash_can_start()
        .expect("enabled component is flashable");

    set_flag(&nv, BankSet::Vm1, true);
    let err = b
        .ensure_flash_can_start()
        .expect_err("a disabled component is not a flash target");
    assert!(
        err.to_string().contains("administratively disabled"),
        "wrong refusal: {err}"
    );
}

#[tokio::test]
async fn read_entity_status_tri_state_and_probe_skip() {
    let nv = make_nv();
    let (addr, probes) = counting_server().await;
    let b =
        vm_backend(&nv, BankSet::Vm1, Some(addr)).with_deactivator(Arc::new(MockDeactivator::ok()));

    // Disabled: NotReady, admin_state "disabled", and the vm-service probe
    // is SKIPPED (zero connections — no phantom health traffic to a VM that
    // is down by design).
    set_flag(&nv, BankSet::Vm1, true);
    let status = b.read_entity_status().await.unwrap();
    assert_eq!(status.status, EntityStatus::NotReady);
    assert_eq!(
        status.extensions["x-sumo-runtime"]["admin_state"], "disabled",
        "disabled read-back"
    );
    assert_eq!(probes.load(Ordering::SeqCst), 0, "probe must be skipped");

    // Enabled again: the probe runs (our canned server is not a healthy
    // guest, so spec status stays notReady — honesty), admin_state "enabled".
    set_flag(&nv, BankSet::Vm1, false);
    let status = b.read_entity_status().await.unwrap();
    assert_eq!(
        status.extensions["x-sumo-runtime"]["admin_state"], "enabled",
        "enabled read-back"
    );
    assert!(
        probes.load(Ordering::SeqCst) > 0,
        "enabled components are probed"
    );
}

#[tokio::test]
async fn probe_component_status_rides_the_uniform_node() {
    // rt-style component: no vm-service, an injected HealthProbe. The probe
    // drives the STANDARD status field and its extensions ride the SAME
    // x-sumo-runtime node as every other component's metadata — never a
    // bespoke per-component route.
    let nv = make_nv();
    let b = vm_backend(&nv, BankSet::Rt, None)
        .with_deactivator(Arc::new(MockDeactivator::ok()))
        .with_health_probe(Arc::new(MockProbe { running: true }));
    let status = b.read_entity_status().await.unwrap();
    assert_eq!(status.status, EntityStatus::Ready, "probe running ⇒ ready");
    let rt = &status.extensions["x-sumo-runtime"];
    assert_eq!(rt["admin_state"], "enabled");
    assert_eq!(rt["m7_total_startup"], 86, "probe extension merged");
    assert_eq!(rt["boot_count"], 0, "standard field wins the collision");
    assert_eq!(rt["hb_seq"], 7, "probe health feeds the uniform fields");

    // Probe not running ⇒ the standard status field is honest.
    let b = vm_backend(&nv, BankSet::Rt, None)
        .with_deactivator(Arc::new(MockDeactivator::ok()))
        .with_health_probe(Arc::new(MockProbe { running: false }));
    let status = b.read_entity_status().await.unwrap();
    assert_eq!(
        status.status,
        EntityStatus::NotReady,
        "probe down ⇒ notReady"
    );

    // Disabled ⇒ minimal read: notReady + admin_state, no probe extensions.
    // Probe not running ⇒ the deactivation is fully realized: no
    // reboot_pending flag.
    b.set_admin_state(true).await.expect("disable admitted");
    let status = b.read_entity_status().await.unwrap();
    assert_eq!(status.status, EntityStatus::NotReady);
    let rt = &status.extensions["x-sumo-runtime"];
    assert_eq!(rt["admin_state"], "disabled");
    assert!(
        rt.get("m7_total_startup").is_none(),
        "disabled read stays minimal"
    );
    assert!(
        rt.get("reboot_pending").is_none(),
        "realized deactivation carries no reboot_pending"
    );

    // Disabled but the probe STILL reports running (rt: erased partition,
    // application executing from SRAM) ⇒ the armed reboot is observable on
    // the uniform node until the real reboot clears it.
    let nv2 = make_nv();
    let b = vm_backend(&nv2, BankSet::Rt, None)
        .with_deactivator(Arc::new(MockDeactivator::ok()))
        .with_health_probe(Arc::new(MockProbe { running: true }));
    set_flag(&nv2, BankSet::Rt, true);
    let status = b.read_entity_status().await.unwrap();
    assert_eq!(
        status.status,
        EntityStatus::NotReady,
        "disabled stays notReady"
    );
    let rt = &status.extensions["x-sumo-runtime"];
    assert_eq!(rt["admin_state"], "disabled");
    assert_eq!(
        rt["reboot_pending"], true,
        "armed reboot must be observable"
    );
}

#[tokio::test]
async fn ecu_reset_skips_vm_service_when_disabled() {
    let nv = make_nv();
    let (addr, hits) = counting_server().await;
    let b =
        vm_backend(&nv, BankSet::Vm1, Some(addr)).with_deactivator(Arc::new(MockDeactivator::ok()));

    // Disabled: a reset must NOT resurrect the VM — zero vm-service traffic
    // (neither the was-running probe nor the start/restart notify).
    set_flag(&nv, BankSet::Vm1, true);
    b.ecu_reset(0x01).await.unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "reset of a disabled component must not touch vm-service"
    );

    // Enabled: the reset notifies vm-service again.
    set_flag(&nv, BankSet::Vm1, false);
    b.ecu_reset(0x01).await.unwrap();
    assert!(
        hits.load(Ordering::SeqCst) > 0,
        "reset of an enabled component notifies vm-service"
    );
}

#[tokio::test]
async fn list_operations_advertises_admin_op_for_disableable() {
    let nv = make_nv();
    let b = vm_backend(&nv, BankSet::Vm1, None).with_deactivator(Arc::new(MockDeactivator::ok()));
    let ops = b.list_operations().await.unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].id, ADMIN_STATE_OP_ID);
    assert_eq!(
        ops[0].href,
        format!("/vehicle/v1/components/vm1/operations/{ADMIN_STATE_OP_ID}/executions")
    );
}

// --- Router (wire) ---------------------------------------------------------

/// A deterministic ES256 issuer keypair (no RNG — stable across runs).
fn issuer_keys() -> (jsonwebtoken::EncodingKey, jsonwebtoken::DecodingKey) {
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    let mut scalar = [0u8; 32];
    scalar[31] = 7;
    let sk = SigningKey::from_bytes(&p256::FieldBytes::from(scalar)).expect("valid scalar");
    let priv_pem = sk.to_pkcs8_pem(LineEnding::LF).expect("pkcs8 pem");
    let pub_pem = sk
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("spki pem");
    (
        jsonwebtoken::EncodingKey::from_ec_pem(priv_pem.as_bytes()).expect("encoding key"),
        jsonwebtoken::DecodingKey::from_ec_pem(pub_pem.as_bytes()).expect("decoding key"),
    )
}

fn mint(enc: &jsonwebtoken::EncodingKey, scopes: &[&str]) -> String {
    use jsonwebtoken::{encode, Algorithm, Header};
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("workshop".to_string());
    let claims = serde_json::json!({
        "sub": "operator",
        "iss": "workshop",
        "aud": "vehicle-1",
        "exp": 9_999_999_999u64,
        "scope": scopes.join(" "),
    });
    encode(&header, &claims, enc).expect("mint")
}

/// The wire rig: vm1 (disableable, mock deactivator) + hsm (not disableable)
/// behind the admin-state router with a real `TieredAuthorizer`.
struct Rig {
    router: axum::Router,
    nv: SharedNv,
    deactivator: Arc<MockDeactivator>,
    enc: jsonwebtoken::EncodingKey,
}

fn rig_with(deactivator: Arc<MockDeactivator>) -> Rig {
    let nv = make_nv();
    let vm1 = Arc::new(vm_backend(&nv, BankSet::Vm1, None).with_deactivator(deactivator.clone()));
    let hsm = Arc::new(hsm_backend(&nv));
    let machine: Arc<dyn Machine> = Arc::new(
        MachineRegistry::builder(EntityInfo {
            id: "vehicle".into(),
            name: "vehicle".into(),
            entity_type: "vehicle".into(),
            description: None,
            href: "/vehicle/v1".into(),
            status: None,
        })
        .with_arc(Arc::new(ComponentAdapter::new(vm1)) as Arc<dyn machine_mgr::Component>)
        .with_arc(Arc::new(ComponentAdapter::new(hsm)) as Arc<dyn machine_mgr::Component>)
        .build(),
    );
    let (enc, dec) = issuer_keys();
    let authorizer: Arc<dyn sovd_api::Authorizer> =
        Arc::new(TieredAuthorizer::new(vec![TrustedIssuer {
            id: "workshop".into(),
            audience: "vehicle-1".into(),
            key: dec,
            ceiling: Tier::Operational,
        }]));
    Rig {
        router: admin_state_router(machine, authorizer),
        nv,
        deactivator,
        enc,
    }
}

fn rig() -> Rig {
    rig_with(Arc::new(MockDeactivator::ok()))
}

/// A token carrying the right verb + a wildcard component scope.
fn admin_token(rig: &Rig) -> String {
    mint(&rig.enc, &["component:*", "component-admin"])
}

async fn post_admin(
    router: &axum::Router,
    component: &str,
    body: serde_json::Value,
    bearer: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let uri =
        format!("/vehicle/v1/components/{component}/operations/{ADMIN_STATE_OP_ID}/executions");
    let mut req = Request::post(&uri).header("content-type", "application/json");
    if let Some(token) = bearer {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let resp = router
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::String(
        String::from_utf8_lossy(&bytes).into_owned(),
    ));
    (status, json)
}

#[tokio::test]
async fn router_401_without_token() {
    let rig = rig();
    let (status, _) = post_admin(
        &rig.router,
        "vm1",
        serde_json::json!({"state": "disabled"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!flag_of(&rig.nv, BankSet::Vm1));
    assert_eq!(rig.deactivator.calls(), 0);
}

#[tokio::test]
async fn router_403_wrong_verb() {
    // A genuine token missing the component-admin verb: verified but denied.
    let rig = rig();
    let token = mint(&rig.enc, &["component:vm1", "data:read"]);
    let (status, body) = post_admin(
        &rig.router,
        "vm1",
        serde_json::json!({"state": "disabled"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    assert_eq!(rig.deactivator.calls(), 0);
}

#[tokio::test]
async fn router_404_unknown_component() {
    let rig = rig();
    let token = admin_token(&rig);
    let (status, _) = post_admin(
        &rig.router,
        "no-such-component",
        serde_json::json!({"state": "disabled"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn router_400_non_disableable() {
    let rig = rig();
    let token = admin_token(&rig);
    let (status, body) = post_admin(
        &rig.router,
        "hsm",
        serde_json::json!({"state": "disabled"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body.as_str()
            .is_some_and(|s| s.contains("does not support administrative disable")),
        "body: {body}"
    );
}

#[tokio::test]
async fn router_400_bad_state_value() {
    let rig = rig();
    let token = admin_token(&rig);
    let (status, _) = post_admin(
        &rig.router,
        "vm1",
        serde_json::json!({"state": "off"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn router_409_while_in_trial() {
    let rig = rig();
    {
        let mut nv = rig.nv.lock().unwrap();
        let mut boot = nv.read_boot_state().unwrap();
        boot.banks[BankSet::Vm1.as_index()].committed = false;
        nv.write_boot_state(&mut boot).unwrap();
    }
    let token = admin_token(&rig);
    let (status, body) = post_admin(
        &rig.router,
        "vm1",
        serde_json::json!({"state": "disabled", "reason": "test rig"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert!(
        body.as_str().is_some_and(|s| s.contains("trial")),
        "the 409 must carry the reason: {body}"
    );
    assert!(!flag_of(&rig.nv, BankSet::Vm1));
}

#[tokio::test]
async fn router_happy_disable_then_enable() {
    let rig = rig();
    let token = admin_token(&rig);

    // Disable: 200, §7.14 execution completed, result {state, reboot_required}.
    let (status, body) = post_admin(
        &rig.router,
        "vm1",
        serde_json::json!({"state": "disabled", "reason": "bench test of vm1 sibling"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["operation_id"], ADMIN_STATE_OP_ID);
    assert_eq!(body["status"], "completed");
    assert_eq!(body["result"]["state"], "disabled");
    assert_eq!(body["result"]["reboot_required"], false);
    assert!(body.get("error").is_none() || body["error"].is_null());
    assert!(flag_of(&rig.nv, BankSet::Vm1), "flag persisted");
    assert_eq!(rig.deactivator.calls(), 1, "deactivator enacted");

    // Idempotent repeat: still 200/completed, no second enact.
    let (status, body) = post_admin(
        &rig.router,
        "vm1",
        serde_json::json!({"state": "disabled"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["result"]["state"], "disabled");
    assert_eq!(rig.deactivator.calls(), 1, "no re-enact on repeat");

    // Enable: 200, flag cleared. (No vm_service_addr on this backend — the
    // no-start branch, i.e. the activator-component shape.)
    let (status, body) = post_admin(
        &rig.router,
        "vm1",
        serde_json::json!({"state": "enabled"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["status"], "completed");
    assert_eq!(body["result"]["state"], "enabled");
    assert!(!flag_of(&rig.nv, BankSet::Vm1), "flag cleared");
}

#[tokio::test]
async fn router_reports_failed_execution_when_enact_fails() {
    // Enact failure ⇒ HTTP 200 (the state change persisted) with the honest
    // §7.14 `failed` status + error — the trials response shape.
    let rig = rig_with(Arc::new(MockDeactivator::failing()));
    let token = admin_token(&rig);
    let (status, body) = post_admin(
        &rig.router,
        "vm1",
        serde_json::json!({"state": "disabled"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["status"], "failed");
    assert_eq!(body["result"]["state"], "disabled");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|e| e.contains("mock enact failure")),
        "body: {body}"
    );
    assert!(flag_of(&rig.nv, BankSet::Vm1), "flag persisted regardless");
}
