//! Integration tests for the per-component administrative state slice: the
//! SUIT disable-manifest enact path (`enact_disable_manifest`), the serving
//! bank's signed sentinel record as the disable authority (`admin_disabled`),
//! and the flash-gate + status + reset enforcement points — mirroring the
//! `sovd_tests.rs` harness style.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use nv_store::block::MemBlockDevice;
use nv_store::slots;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::*;

use machine_mgr::bank_provider::{BankProvider, FirmwareIdentity};
use machine_mgr::{
    DeactivateError, DeactivateOutcome, Deactivator, InMemorySelectorStore, SharedSystemBankState,
    SystemBankManager, TestSigner,
};
use sovd_core::{BackendError, DiagnosticBackend, EntityStatus, PackageStream};

use component_mgr::backend::{ComponentBackend, ComponentConfig, INSTALLED_MANIFEST_PARAM_ID};
use component_mgr::bank_provider::IvdBankProvider;
use component_mgr::manifest_provider::{
    ManifestError, ManifestProvider, ManifestType, ValidatedFirmware,
};
use component_mgr::ota::ImageMeta;
use sumo_offboard::{keygen, ImageManifestBuilder};

// --- Harness ---------------------------------------------------------------

/// Manifest validation is never reached by the admin-state paths — a stub
/// keeps the harness free of the SUIT/key machinery.
struct StubManifests;
impl ManifestProvider for StubManifests {
    fn validate(&self, _data: &[u8], _min: u32) -> Result<ValidatedFirmware, ManifestError> {
        Err(ManifestError::ParseError("stub".into()))
    }
}

/// Provider that yields a pre-baked no-payload `ValidatedFirmware`: a disable
/// manifest when `disable_target` is `Some`, an ordinary CRL/policy no-op when
/// `None`. The raw upload bytes are ignored — the disable routing keys off the
/// flag the real `SuitProvider` sets from the manifest's shared sequence.
struct CannedManifest {
    component_name: String,
    disable_target: Option<usize>,
}
impl ManifestProvider for CannedManifest {
    fn validate(&self, _data: &[u8], _min: u32) -> Result<ValidatedFirmware, ManifestError> {
        Ok(ValidatedFirmware {
            component_name: self.component_name.clone(),
            manifest_type: ManifestType::Firmware,
            image_meta: ImageMeta::default(),
            image_data: Vec::new(),
            version_display: "disable".into(),
            image_sha256: None,
            image_size: None,
            raw_envelope: None,
            streamed_files: Vec::new(),
            signing_time_secs: None,
            disable_target: self.disable_target,
        })
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
    fn rebooting() -> Self {
        Self {
            reboot_required: true,
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

/// Backend wired with a caller-supplied manifest provider (the disable-upload
/// tests swap in `CannedManifest`; the rest use `StubManifests`).
fn backend_with_manifests(
    nv: &SharedNv,
    set: BankSet,
    id: &str,
    manifests: Arc<dyn ManifestProvider>,
) -> ComponentBackend<MemBlockDevice> {
    ComponentBackend::with_options(
        set,
        nv.clone(),
        manifests,
        ComponentConfig::default(),
        None,
        None,
        None,
    )
    // The manifest names a COMPONENT; the backend's own id is what it's
    // checked against, so the fixture threads it like the factory does.
    .with_id(id.to_string())
}

/// A shared boot selector with a booted selection for `set` (bank A) — the
/// serving bank a component's disable record is read from.
fn selector_for(set: BankSet) -> SharedSystemBankState {
    let mgr = SystemBankManager::load(Box::new(InMemorySelectorStore::new()), Box::new(TestSigner));
    let shared: SharedSystemBankState = Arc::new(std::sync::RwLock::new(mgr));
    {
        let mut g = shared.write().unwrap();
        g.stage(set, Bank::A);
        g.seal();
    }
    shared
}

/// Point the selector's booted selection for `set` at `bank` — what a flash's
/// `activate` does. Re-enable is structural: once the serving bank holds no
/// sentinel, `admin_disabled()` reads enabled.
fn serve_bank(sel: &SharedSystemBankState, set: BankSet, bank: Bank) {
    let mut g = sel.write().unwrap();
    g.stage(set, bank);
    g.seal();
}

/// Provision the IVD-signing slot in a fresh keystore dir. Reproduces
/// `partition_bank.rs`'s `provisioned_keystore` (an integration test can't
/// reach another test crate's helpers).
fn provisioned_keystore(tmp: &Path) -> PathBuf {
    use hsm::payload::*;
    let ks_dir = tmp.join("keystore");
    std::fs::create_dir_all(&ks_dir).unwrap();
    let hsm = hsm_sim_backend::SimHsm::new(ks_dir.clone());
    hsm.write_keystore(&HsmKeystore {
        schema_version: SCHEMA_VERSION,
        security_version: 1,
        identities: vec![],
        slots: vec![KeySlot {
            key_id: hsm::ivd::IVD_KEY_ID.to_string(),
            key_kind: KEY_TYPE_EC_P256,
            anchor_public_key: None,
            allowed_guests: None,
            allowed_ops: Some(vec![OP_SIGN, OP_VERIFY, OP_GET_PUBKEY]),
        }],
        certificates: Vec::new(),
        trust_anchors: Vec::new(),
    })
    .unwrap();
    std::fs::write(ks_dir.join("provision_state"), b"1\n").unwrap();
    ks_dir
}

/// A `vm1`-dir `IvdBankProvider` that can SIGN: an on-disk `images_dir` under
/// `tmp` and a provisioned SimHsm as both its provisioning authority and its
/// crypto handle — so the disable record is written and read for real, the
/// production shape. `selector`, when given, is the boot authority it follows.
fn signing_provider(
    nv: &SharedNv,
    set: BankSet,
    selector: Option<SharedSystemBankState>,
    tmp: &Path,
) -> Arc<IvdBankProvider<MemBlockDevice>> {
    let ks = provisioned_keystore(tmp);
    let hsm: Arc<Mutex<dyn hsm::HsmProvider>> =
        Arc::new(Mutex::new(hsm_sim_backend::SimHsm::new(ks.clone())));
    Arc::new(
        IvdBankProvider::new(
            nv.clone(),
            set,
            false,
            Some(tmp.join("images")),
            "vm1".into(),
            Some(hsm),
            None,
            selector,
        )
        .with_hsm_crypto(Arc::new(hsm_sim_backend::SimHsm::new(ks))),
    )
}

/// As [`signing_provider`], but for a single-bank (rt-shaped) component: the
/// provider's `single_bank` flag is set and `dir_name` is `id` — the shape
/// `sovd_tests.rs`'s `make_disable_router("rt", …)` wires, where the live
/// bank IS the only bank and a flash targets it in place.
fn single_bank_signing_provider(
    nv: &SharedNv,
    set: BankSet,
    id: &str,
    selector: Option<SharedSystemBankState>,
    tmp: &Path,
) -> Arc<IvdBankProvider<MemBlockDevice>> {
    let ks = provisioned_keystore(tmp);
    let hsm: Arc<Mutex<dyn hsm::HsmProvider>> =
        Arc::new(Mutex::new(hsm_sim_backend::SimHsm::new(ks.clone())));
    Arc::new(
        IvdBankProvider::new(
            nv.clone(),
            set,
            true,
            Some(tmp.join("images")),
            id.into(),
            Some(hsm),
            None,
            selector,
        )
        .with_hsm_crypto(Arc::new(hsm_sim_backend::SimHsm::new(ks))),
    )
}

/// `ComponentConfig` for the rt-shaped single-bank tests — the same shape
/// `sovd_tests.rs`'s `make_disable_router("rt", …)` wires.
fn rt_config() -> ComponentConfig {
    ComponentConfig {
        supports_rollback: false,
        single_bank: true,
        entity_type: "rt".into(),
        ..ComponentConfig::default()
    }
}

/// A single-bank (rt-shaped) backend over a caller-supplied `provider` and
/// manifest provider — the direct-construction analogue of
/// [`backend_with_manifests`] for the [`single_bank_signing_provider`] shape.
fn rt_backend_with_manifests(
    nv: &SharedNv,
    manifests: Arc<dyn ManifestProvider>,
    provider: Arc<IvdBankProvider<MemBlockDevice>>,
) -> ComponentBackend<MemBlockDevice> {
    ComponentBackend::with_options(
        slots::RT,
        nv.clone(),
        manifests,
        rt_config(),
        None,
        None,
        None,
    )
    .with_id("rt".to_string())
    .with_bank_provider(provider)
}

/// `bank`'s installed-firmware gen (NvFwMeta) — the gen a disable ratchets
/// from — writing gen 1 first when the fixture has none.
fn installed_gen(nv: &SharedNv, set: BankSet, bank: Bank) -> u64 {
    let mut nv = nv.lock().unwrap();
    if let Some(meta) = nv.read_fw_meta(set, bank) {
        return meta.gen;
    }
    let mut meta = NvFwMeta {
        gen: 1,
        ..Default::default()
    };
    nv.write_fw_meta(set, bank, &mut meta).unwrap();
    1
}

/// Persist a disable the way the enact does, minus the enact itself: `bank`'s
/// signed sentinel record at its NvFwMeta gen — what `admin_disabled()` reads.
/// Written behind the backend's back, so it must land before that backend
/// first derives its admin state (the derived state is cached until NV or the
/// serving bank changes).
fn write_sentinel(
    provider: &IvdBankProvider<MemBlockDevice>,
    nv: &SharedNv,
    set: BankSet,
    bank: Bank,
) {
    let gen = installed_gen(nv, set, bank);
    provider.write_disabled_record(bank, gen).unwrap();
}

/// A vm-style backend whose bank provider is wired to `selector` and can sign
/// ([`signing_provider`] under `tmp`), so the disable read/write paths run for
/// real. Hands the provider back for `write_sentinel` and on-disk assertions.
fn vm_backend_with_selector(
    nv: &SharedNv,
    set: BankSet,
    vm_service_addr: Option<String>,
    selector: SharedSystemBankState,
    tmp: &Path,
) -> (
    ComponentBackend<MemBlockDevice>,
    Arc<IvdBankProvider<MemBlockDevice>>,
) {
    let provider = signing_provider(nv, set, Some(selector), tmp);
    let backend = vm_backend(nv, set, vm_service_addr).with_bank_provider(provider.clone());
    (backend, provider)
}

/// The pre-step-2 health body: an older vm-service that reports no intent at
/// all. Kept as the default so the mixed-pin case (newer host, older
/// vm-service) is what most tests exercise.
const HEALTH_WITHOUT_INTENT: &str =
    r#"{"status":"stopped","guest_state":null,"hb_seq":null,"boot_id":null}"#;

/// Serve canned `200 OK`s on an ephemeral loopback port, counting accepted
/// connections — the observable for "did anything talk to vm-service?".
async fn counting_server() -> (String, Arc<AtomicUsize>) {
    counting_server_with_health(HEALTH_WITHOUT_INTENT).await
}

/// As [`counting_server`], with the health body to serve — so a test can pin
/// what a host does with an intent-carrying body and with one lacking it.
async fn counting_server_with_health(health: &'static str) -> (String, Arc<AtomicUsize>) {
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
                let size = stream.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..size]);
                let body = if request.starts_with("GET ") {
                    health
                } else {
                    ""
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    (addr, count)
}

/// As [`counting_server`], but the counter records only POST requests — the
/// vm-service (re)start/restart notify `ecu_reset` issues — so the GET health
/// probe `ecu_reset` also makes on the same address does not inflate the
/// count. GET still gets [`HEALTH_WITHOUT_INTENT`]: the health baseline
/// `ecu_reset` must establish before it will notify at all.
async fn counting_post_server() -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let c = c.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 512];
                let size = stream.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..size]);
                let body = if request.starts_with("GET ") {
                    HEALTH_WITHOUT_INTENT
                } else {
                    if request.starts_with("POST ") {
                        c.fetch_add(1, Ordering::SeqCst);
                    }
                    ""
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    (addr, count)
}

// --- Backend semantics -----------------------------------------------------

#[tokio::test]
async fn non_disableable_component_omits_admin_state() {
    // No deactivator ⇒ not disableable. `admin_disabled()` short-circuits on
    // `is_disableable()`, so even a sentinel on the serving bank reads as
    // enabled — the equipped deactivator is the authority.
    let nv = make_nv();
    let tmp = tempfile::tempdir().unwrap();
    let (b, provider) =
        vm_backend_with_selector(&nv, slots::VM1, None, selector_for(slots::VM1), tmp.path());
    assert!(!b.is_disableable());

    write_sentinel(&provider, &nv, slots::VM1, Bank::A);
    assert!(
        !b.admin_disabled(),
        "a sentinel on a non-disableable component reads as enabled"
    );

    // No admin_state field in /status (tri-state read-back), no advertised op.
    let status = b.read_entity_status().await.unwrap();
    let runtime = &status.extensions["x-runtime"];
    assert!(
        runtime.get("admin_state").is_none(),
        "non-disableable components must omit admin_state entirely"
    );
    assert!(b.list_operations().await.unwrap().is_empty());
}

#[tokio::test]
async fn ensure_flash_can_start_admits_disabled() {
    // A disabled component is NOT refused here: a flash re-enables it
    // structurally (a real IVD sealed into the target, the selector moved
    // there), so the gate must admit it. The "disabled ⇒ never uncommitted"
    // invariant holds because the disable enact refuses a component mid-trial,
    // not by refusing at this gate.
    let nv = make_nv();
    let tmp = tempfile::tempdir().unwrap();
    let (b, provider) =
        vm_backend_with_selector(&nv, slots::VM1, None, selector_for(slots::VM1), tmp.path());
    let b = b.with_deactivator(Arc::new(MockDeactivator::ok()));
    b.ensure_flash_can_start()
        .expect("enabled component is flashable");

    write_sentinel(&provider, &nv, slots::VM1, Bank::A);
    assert!(
        b.admin_disabled(),
        "precondition: the component is disabled"
    );
    b.ensure_flash_can_start()
        .expect("a disabled component is admitted (a flash re-enables it)");
}

#[tokio::test]
async fn read_entity_status_tri_state_and_probe_skip() {
    let nv = make_nv();
    let (addr, probes) = counting_server().await;
    let tmp = tempfile::tempdir().unwrap();
    let sel = selector_for(slots::VM1);
    let (b, provider) =
        vm_backend_with_selector(&nv, slots::VM1, Some(addr), sel.clone(), tmp.path());
    let b = b.with_deactivator(Arc::new(MockDeactivator::ok()));

    // Disabled: NotReady, admin_state "disabled", and the vm-service probe
    // is SKIPPED (zero connections — no phantom health traffic to a VM that
    // is down by design).
    write_sentinel(&provider, &nv, slots::VM1, Bank::A);
    let status = b.read_entity_status().await.unwrap();
    assert_eq!(status.status, EntityStatus::NotReady);
    let rt = &status.extensions["x-runtime"];
    assert_eq!(rt["admin_state"], "disabled", "disabled read-back");
    assert_eq!(probes.load(Ordering::SeqCst), 0, "probe must be skipped");
    // Down by design now SAYS so on the intent axis, instead of leaving every
    // reader to infer it from `admin_state`. `lifecycle_status` used to be
    // missing here entirely while `runtime_state` published one.
    assert_eq!(rt["lifecycle_status"], "stopped");
    assert_eq!(rt["lifecycle_expected"], "stopped");
    assert_eq!(rt["lifecycle_expected_by"], "admin_disable");
    assert!(
        rt.get("lifecycle_convergence").is_none(),
        "nothing was polled, so no verdict may be claimed: {rt}"
    );

    // Enabled again — structurally, the selector now serving a bank with no
    // sentinel (what a flash's activate does): the probe runs (our canned
    // server is not a healthy guest, so spec status stays notReady — honesty),
    // admin_state "enabled".
    serve_bank(&sel, slots::VM1, Bank::B);
    let status = b.read_entity_status().await.unwrap();
    let rt = &status.extensions["x-runtime"];
    assert_eq!(rt["admin_state"], "enabled", "enabled read-back");
    assert!(
        probes.load(Ordering::SeqCst) > 0,
        "enabled components are probed"
    );
    // The mixed-pin case: a step-2 host against a vm-service that publishes no
    // intent. It must not invent one — no intent, no verdict.
    assert_eq!(rt["lifecycle_status"], "stopped");
    assert!(rt.get("lifecycle_expected").is_none(), "{rt}");
    assert!(rt.get("lifecycle_convergence").is_none(), "{rt}");
    // And the spec field is untouched by any of this: adding the axis changed no
    // gate. `EntityStatus` still answers only "can this serve requests".
    assert_eq!(status.status, EntityStatus::NotReady);
}

#[tokio::test]
async fn disabled_status_and_runtime_state_agree() {
    // These two views of the same component used to disagree: /status published
    // no `lifecycle_*` for a disabled component (health = None ⇒ the writer
    // never ran) while `runtime_state` hand-built its own `lifecycle_status` +
    // reason. One writer now — this test is what keeps them from drifting apart
    // again.
    let nv = make_nv();
    let (addr, _probes) = counting_server().await;
    let tmp = tempfile::tempdir().unwrap();
    let (b, provider) = vm_backend_with_selector(
        &nv,
        slots::VM1,
        Some(addr),
        selector_for(slots::VM1),
        tmp.path(),
    );
    let b = b.with_deactivator(Arc::new(MockDeactivator::ok()));
    write_sentinel(&provider, &nv, slots::VM1, Bank::A);

    let status = b.read_entity_status().await.unwrap();
    let rt = status.extensions["x-runtime"].as_object().unwrap().clone();
    let detail = b.runtime_state_snapshot().await.detail;
    let detail = detail.as_object().unwrap();

    for key in [
        "lifecycle_status",
        "lifecycle_reason",
        "lifecycle_expected",
        "lifecycle_expected_by",
    ] {
        assert_eq!(
            rt.get(key),
            detail.get(key),
            "/status and runtime_state disagree about {key}"
        );
    }
    assert!(
        !rt.contains_key("lifecycle_convergence") && !detail.contains_key("lifecycle_convergence"),
        "neither view may claim a verdict it did not observe"
    );
}

#[tokio::test]
async fn a_guest_that_was_asked_to_run_and_is_not_reads_diverged() {
    // The case step 1 could publish but not judge: down with a reason, which is
    // indistinguishable from a deliberate stop until the intent axis says a
    // start was requested. Now one key answers it — and the two clocks let the
    // observer see the component has been down 90 s but only WRONGLY down 30 s.
    let nv = make_nv();
    let (addr, _probes) = counting_server_with_health(
        r#"{"status":"stopped","reason":"no active bank selected","for_ms":90000,
            "expected":"running","expected_by":"autostart","expected_for_ms":30000}"#,
    )
    .await;
    let b = vm_backend(&nv, slots::VM1, Some(addr));

    let status = b.read_entity_status().await.unwrap();
    let rt = &status.extensions["x-runtime"];
    assert_eq!(rt["lifecycle_convergence"], "diverged");
    assert_eq!(rt["lifecycle_expected"], "running");
    assert_eq!(rt["lifecycle_expected_by"], "autostart");
    assert_eq!(rt["lifecycle_for_ms"], 90000);
    assert_eq!(rt["lifecycle_expected_for_ms"], 30000);
    assert_eq!(rt["lifecycle_reason"], "no active bank selected");
    // A divergence is not a gate: `EntityStatus` was already notReady for this
    // guest and nothing about the verdict changes it. Retargeting waits onto the
    // verdict is a separate, deliberate step.
    assert_eq!(status.status, EntityStatus::NotReady);
}

#[tokio::test]
async fn probe_component_status_rides_the_uniform_node() {
    // rt-style component: no vm-service, an injected HealthProbe. The probe
    // drives the STANDARD status field and its extensions ride the SAME
    // x-runtime node as every other component's metadata — never a
    // bespoke per-component route.
    let nv = make_nv();
    let b = vm_backend(&nv, slots::RT, None)
        .with_deactivator(Arc::new(MockDeactivator::ok()))
        .with_health_probe(Arc::new(MockProbe { running: true }));
    let status = b.read_entity_status().await.unwrap();
    assert_eq!(status.status, EntityStatus::Ready, "probe running ⇒ ready");
    let rt = &status.extensions["x-runtime"];
    assert_eq!(rt["admin_state"], "enabled");
    assert_eq!(rt["m7_total_startup"], 86, "probe extension merged");
    assert_eq!(rt["boot_count"], 0, "standard field wins the collision");
    assert_eq!(rt["hb_seq"], 7, "probe health feeds the uniform fields");

    // Probe not running ⇒ the standard status field is honest.
    let tmp = tempfile::tempdir().unwrap();
    let (b, provider) =
        vm_backend_with_selector(&nv, slots::RT, None, selector_for(slots::RT), tmp.path());
    let b = b
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
    // reboot_pending flag. A fresh backend over the same bank reads it: the
    // record lands behind `b`'s back, and `b` keeps the state it derived above.
    write_sentinel(&provider, &nv, slots::RT, Bank::A);
    let b = vm_backend(&nv, slots::RT, None)
        .with_bank_provider(provider.clone())
        .with_deactivator(Arc::new(MockDeactivator::ok()))
        .with_health_probe(Arc::new(MockProbe { running: false }));
    let status = b.read_entity_status().await.unwrap();
    assert_eq!(status.status, EntityStatus::NotReady);
    let rt = &status.extensions["x-runtime"];
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
    let tmp2 = tempfile::tempdir().unwrap();
    let (b, provider2) =
        vm_backend_with_selector(&nv2, slots::RT, None, selector_for(slots::RT), tmp2.path());
    let b = b
        .with_deactivator(Arc::new(MockDeactivator::ok()))
        .with_health_probe(Arc::new(MockProbe { running: true }));
    write_sentinel(&provider2, &nv2, slots::RT, Bank::A);
    let status = b.read_entity_status().await.unwrap();
    assert_eq!(
        status.status,
        EntityStatus::NotReady,
        "disabled stays notReady"
    );
    let rt = &status.extensions["x-runtime"];
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
    let tmp = tempfile::tempdir().unwrap();
    let sel = selector_for(slots::VM1);
    let (b, provider) =
        vm_backend_with_selector(&nv, slots::VM1, Some(addr), sel.clone(), tmp.path());
    let b = b.with_deactivator(Arc::new(MockDeactivator::ok()));

    // Disabled: a reset must NOT resurrect the VM — zero vm-service traffic
    // (neither the was-running probe nor the start/restart notify).
    write_sentinel(&provider, &nv, slots::VM1, Bank::A);
    b.ecu_reset(0x01).await.unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "reset of a disabled component must not touch vm-service"
    );

    // Enabled (the selector now serves a bank with no sentinel): the reset
    // notifies vm-service again.
    serve_bank(&sel, slots::VM1, Bank::B);
    b.ecu_reset(0x01).await.unwrap();
    assert!(
        hits.load(Ordering::SeqCst) > 0,
        "reset of an enabled component notifies vm-service"
    );
}

// --- Disable-manifest upload routing ---------------------------------------
// A SUIT disable manifest (no payload) uploaded to a component's package
// endpoint routes to that component's `Deactivator` instead of the CRL/policy
// no-op — the single-shot `receive_package` path (the streaming path shares the
// same `enact_disable_manifest` helper).

#[tokio::test]
async fn disable_manifest_upload_enacts_deactivator_and_handles_reboot() {
    let nv = make_nv();
    let tmp = tempfile::tempdir().unwrap();
    installed_gen(&nv, slots::VM1, Bank::A);
    let deact = Arc::new(MockDeactivator::rebooting());
    let b = backend_with_manifests(
        &nv,
        slots::VM1,
        "vm1",
        Arc::new(CannedManifest {
            component_name: "vm1".into(),
            disable_target: Some(0),
        }),
    )
    .with_bank_provider(signing_provider(&nv, slots::VM1, None, tmp.path()))
    .with_deactivator(deact.clone());

    // Routes to the deactivator (not stored as a package); reboot_required=true
    // is handled (captured, non-fatal).
    b.receive_package(b"disable-envelope")
        .await
        .expect("disable manifest enacted");
    assert_eq!(deact.calls(), 1, "deactivate() invoked exactly once");
}

#[tokio::test]
async fn suit_disable_manifest_writes_sentinel_and_start_flash_admits() {
    // A SUIT disable manifest on the single-shot `receive_package` path routes to
    // `enact_disable_manifest`, which persists the disable as the serving bank's
    // signed sentinel record at its (ratcheted) NvFwMeta gen; `admin_disabled()`
    // reads it back. `start_flash` admits a disabled component and clears
    // nothing: a flash re-enables structurally, by activating a real IVD (see
    // `campaign_normal_flash_reenables_by_activating_a_real_ivd`).
    let nv = make_nv();
    let tmp = tempfile::tempdir().unwrap();
    installed_gen(&nv, slots::VM1, Bank::A);
    let provider = signing_provider(&nv, slots::VM1, Some(selector_for(slots::VM1)), tmp.path());
    let deact = Arc::new(MockDeactivator::ok());
    let b = backend_with_manifests(
        &nv,
        slots::VM1,
        "vm1",
        Arc::new(CannedManifest {
            component_name: "vm1".into(),
            disable_target: Some(0),
        }),
    )
    .with_deactivator(deact.clone())
    .with_bank_provider(provider.clone());

    assert!(!b.admin_disabled(), "starts enabled");

    // Disable via the SUIT manifest → deactivate + the sentinel record.
    b.receive_package(b"disable-envelope")
        .await
        .expect("disable manifest enacted");
    assert_eq!(deact.calls(), 1, "deactivator enacted once");
    let gen = nv
        .lock()
        .unwrap()
        .read_fw_meta(slots::VM1, Bank::A)
        .unwrap()
        .gen;
    assert_eq!(
        provider.disabled_record(Bank::A).unwrap(),
        Some(gen),
        "the serving bank holds the sentinel at its NvFwMeta gen"
    );
    assert!(b.admin_disabled(), "admin_disabled() reads the sentinel");

    // `start_flash` ADMITS a disabled component and clears nothing.
    b.start_flash()
        .await
        .expect("start_flash admits a disabled component");
    assert!(
        b.admin_disabled(),
        "still disabled until a flash activates a real bank"
    );
}

#[tokio::test]
async fn non_disable_no_payload_manifest_is_a_noop() {
    let nv = make_nv();
    let deact = Arc::new(MockDeactivator::ok());
    let b = backend_with_manifests(
        &nv,
        slots::VM1,
        "vm1",
        Arc::new(CannedManifest {
            component_name: "vm1".into(),
            disable_target: None,
        }),
    )
    .with_deactivator(deact.clone());

    // No disable directive ⇒ genuine CRL/policy no-op: stored as a package, the
    // deactivator is never touched.
    let id = b
        .receive_package(b"crl-envelope")
        .await
        .expect("no-op manifest accepted");
    assert!(!id.is_empty());
    assert_eq!(
        deact.calls(),
        0,
        "no deactivate() for a non-disable manifest"
    );
}

#[tokio::test]
async fn disable_manifest_without_deactivator_errors() {
    let nv = make_nv();
    // No `.with_deactivator(...)` — this component is not disableable.
    let b = backend_with_manifests(
        &nv,
        slots::VM1,
        "vm1",
        Arc::new(CannedManifest {
            component_name: "vm1".into(),
            disable_target: Some(0),
        }),
    );
    let err = b
        .receive_package(b"disable-envelope")
        .await
        .expect_err("a non-disableable component must reject a disable manifest");
    assert!(
        matches!(err, BackendError::NotSupported(_)),
        "expected NotSupported, got {err:?}"
    );
}

#[tokio::test]
async fn disable_manifest_enact_failure_is_reported() {
    let nv = make_nv();
    let tmp = tempfile::tempdir().unwrap();
    let gen_before = installed_gen(&nv, slots::VM1, Bank::A);
    let provider = signing_provider(&nv, slots::VM1, None, tmp.path());
    let deact = Arc::new(MockDeactivator::failing());
    let b = backend_with_manifests(
        &nv,
        slots::VM1,
        "vm1",
        Arc::new(CannedManifest {
            component_name: "vm1".into(),
            disable_target: Some(0),
        }),
    )
    .with_bank_provider(provider.clone())
    .with_deactivator(deact.clone());
    let err = b
        .receive_package(b"disable-envelope")
        .await
        .expect_err("a failing deactivator must surface an error");
    assert_eq!(deact.calls(), 1);
    assert!(matches!(err, BackendError::Internal(_)), "got {err:?}");
    // Enact-first: a failed enact persists nothing — no record in the serving
    // bank.
    let serving_dir = provider.target_bank_dir(Bank::A).unwrap();
    assert!(
        !serving_dir.join(hsm::ivd::IVD_MANIFEST_FILE).exists(),
        "a failed enact writes no IVD manifest"
    );
    assert_eq!(
        provider.disabled_record(Bank::A).unwrap(),
        None,
        "no sentinel record after a failed enact"
    );
    let gen_after = nv
        .lock()
        .unwrap()
        .read_fw_meta(slots::VM1, Bank::A)
        .unwrap()
        .gen;
    assert_eq!(
        gen_after, gen_before,
        "NvFwMeta gen must be unchanged after a failed enact"
    );
}

/// A disable is refused while the component is mid-trial: the sentinel would
/// land on a bank the pending verdict may still roll away from. `Busy` — the
/// flash gate's answer to the same state — and nothing is enacted.
#[tokio::test]
async fn enact_refuses_when_not_idle() {
    let nv = make_nv();
    let tmp = tempfile::tempdir().unwrap();
    installed_gen(&nv, slots::VM1, Bank::A);
    {
        let mut nv = nv.lock().unwrap();
        let mut boot = nv.read_boot_state().unwrap();
        boot.banks[slots::VM1.as_index()].committed = false;
        nv.write_boot_state(&mut boot).unwrap();
    }
    let deact = Arc::new(MockDeactivator::ok());
    let b = backend_with_manifests(
        &nv,
        slots::VM1,
        "vm1",
        Arc::new(CannedManifest {
            component_name: "vm1".into(),
            disable_target: Some(0),
        }),
    )
    .with_bank_provider(signing_provider(&nv, slots::VM1, None, tmp.path()))
    .with_deactivator(deact.clone());

    let err = b
        .receive_package(b"disable-envelope")
        .await
        .expect_err("a mid-trial component must refuse a disable");
    assert!(matches!(err, BackendError::Busy(_)), "got {err:?}");
    assert_eq!(deact.calls(), 0, "nothing is enacted");
}

/// With no installed-firmware gen on the serving bank there is nothing to
/// ratchet and nothing to disable: refused before the deactivator runs, and no
/// sentinel is invented at gen 0.
#[tokio::test]
async fn enact_refuses_without_gen_source() {
    let nv = make_nv();
    let tmp = tempfile::tempdir().unwrap();
    let provider = signing_provider(&nv, slots::VM1, None, tmp.path());
    let deact = Arc::new(MockDeactivator::ok());
    let b = backend_with_manifests(
        &nv,
        slots::VM1,
        "vm1",
        Arc::new(CannedManifest {
            component_name: "vm1".into(),
            disable_target: Some(0),
        }),
    )
    .with_bank_provider(provider.clone())
    .with_deactivator(deact.clone());

    let err = b
        .receive_package(b"disable-envelope")
        .await
        .expect_err("no gen source must refuse the disable");
    assert!(
        matches!(err, BackendError::PreconditionFailed(_)),
        "got {err:?}"
    );
    assert_eq!(deact.calls(), 0, "refused before the deactivator runs");
    assert_eq!(provider.disabled_record(Bank::A).unwrap(), None);
}

/// The enact ratchets the serving bank's NvFwMeta gen by one and signs the
/// sentinel at exactly that gen — the pair the launch gate's gen pin checks.
#[tokio::test]
async fn enact_ratchets_gen() {
    let nv = make_nv();
    let tmp = tempfile::tempdir().unwrap();
    let old = installed_gen(&nv, slots::VM1, Bank::A);
    let provider = signing_provider(&nv, slots::VM1, None, tmp.path());
    let b = backend_with_manifests(
        &nv,
        slots::VM1,
        "vm1",
        Arc::new(CannedManifest {
            component_name: "vm1".into(),
            disable_target: Some(0),
        }),
    )
    .with_bank_provider(provider.clone())
    .with_deactivator(Arc::new(MockDeactivator::ok()));

    b.receive_package(b"disable-envelope")
        .await
        .expect("disable manifest enacted");
    let gen = nv
        .lock()
        .unwrap()
        .read_fw_meta(slots::VM1, Bank::A)
        .unwrap()
        .gen;
    assert_eq!(gen, old + 1, "NvFwMeta ratcheted by one");
    assert_eq!(
        provider.disabled_record(Bank::A).unwrap(),
        Some(old + 1),
        "the sentinel is signed at the ratcheted gen"
    );
}

/// Only a sentinel at the serving bank's NvFwMeta gen disables: one at any
/// other gen (a moved or pre-ratchet record) is stale and reads as enabled.
#[tokio::test]
async fn admin_disabled_is_false_for_a_stale_sentinel_gen() {
    let nv = make_nv();
    let tmp = tempfile::tempdir().unwrap();
    let (b, provider) =
        vm_backend_with_selector(&nv, slots::VM1, None, selector_for(slots::VM1), tmp.path());
    let b = b.with_deactivator(Arc::new(MockDeactivator::ok()));
    let gen = installed_gen(&nv, slots::VM1, Bank::A);
    provider.write_disabled_record(Bank::A, gen + 1).unwrap();
    assert_eq!(
        provider.disabled_record(Bank::A).unwrap(),
        Some(gen + 1),
        "precondition: the sentinel itself verifies"
    );
    assert!(
        !b.admin_disabled(),
        "a sentinel off the NvFwMeta gen is stale: enabled"
    );
}

#[tokio::test]
async fn disable_manifest_for_other_component_is_rejected_before_enact() {
    let nv = make_nv();
    let deact = Arc::new(MockDeactivator::ok());
    // Manifest names "vm2" but is POSTed to the "vm1" backend — the name guard
    // rejects it before any enact (no cross-component dispatch). The comparison
    // is name-to-id, verbatim; no slot is consulted on either side.
    let b = backend_with_manifests(
        &nv,
        slots::VM1,
        "vm1",
        Arc::new(CannedManifest {
            component_name: "vm2".into(),
            disable_target: Some(0),
        }),
    )
    .with_deactivator(deact.clone());
    let err = b
        .receive_package(b"disable-envelope")
        .await
        .expect_err("cross-component disable must be rejected");
    match err {
        BackendError::InvalidRequest(ref msg) => assert_eq!(
            msg, "manifest targets 'vm2', but this is 'vm1'",
            "the rejection names both components"
        ),
        other => panic!("expected InvalidRequest, got {other:?}"),
    }
    assert_eq!(
        deact.calls(),
        0,
        "deactivator must not run on a component-name mismatch"
    );
}

// --- Campaign/session lifecycle: disable enact + re-enable at finalize --------
// The single-shot `receive_package` tests above do NOT exercise the campaign
// path (`start_flash` → `upload_envelope` → `finalize_flash`) where the disable
// is parked and enacted. These drive that real lifecycle end-to-end.

/// A minimal detached (no integrated payload) single-component SUIT envelope —
/// just enough that `handle_manifest_upload`'s envelope decode succeeds and the
/// session parks in `AwaitingPayload`. The disable-vs-normal decision is supplied
/// by the wired `CannedManifest`, not by this envelope's contents.
fn detached_envelope() -> Vec<u8> {
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    ImageManifestBuilder::new()
        .signing_time(1_700_000_000)
        .component_id(vec!["vm1".into(), "firmware".into()])
        .sequence_number(2)
        .payload_digest(&[0u8; 32], 0)
        .payload_uri("#firmware".into())
        .build(&key)
        .unwrap()
}

/// A detached single-component envelope for vm1's `firmware` part declaring
/// `image`'s real digest, so the payload upload that follows passes the
/// pipeline's digest check and the target bank is sealed for real.
fn firmware_envelope(image: &[u8]) -> Vec<u8> {
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    ImageManifestBuilder::new()
        .signing_time(1_700_000_000)
        .component_id(vec!["vm1".into(), "firmware".into()])
        .sequence_number(2)
        .payload_digest(&Sha256::digest(image), image.len() as u64)
        .payload_uri("#firmware".into())
        .build(&key)
        .unwrap()
}

/// Wrap envelope bytes as the single-chunk `PackageStream` the upload path reads.
fn envelope_stream(data: Vec<u8>) -> PackageStream {
    Box::pin(futures::stream::iter(vec![Ok::<
        bytes::Bytes,
        Box<dyn std::error::Error + Send + Sync>,
    >(bytes::Bytes::from(data))]))
}

/// A vm1 backend wired with `CannedManifest` (so the campaign manifest upload
/// validates to the desired disable/normal shape) AND a selector-backed provider
/// that can sign ([`signing_provider`] under `tmp`), so the disable record is
/// written and read for real. Hands the provider back.
fn campaign_backend(
    nv: &SharedNv,
    manifests: Arc<dyn ManifestProvider>,
    sel: &SharedSystemBankState,
    tmp: &Path,
) -> (
    ComponentBackend<MemBlockDevice>,
    Arc<IvdBankProvider<MemBlockDevice>>,
) {
    let provider = signing_provider(nv, slots::VM1, Some(sel.clone()), tmp);
    let backend = backend_with_manifests(nv, slots::VM1, "vm1", manifests)
        .with_bank_provider(provider.clone());
    (backend, provider)
}

/// As [`campaign_backend`], but wired to a vm-service address and reusing an
/// EXISTING signing provider instead of building a fresh one: the reset test
/// needs one provider shared across two backend instances (the manifest shape
/// is fixed per backend, so re-enabling needs a second one — same reason as
/// `rollback_of_reenable_lands_disabled_and_stops_the_guest`) AND vm-service
/// traffic to count.
fn campaign_backend_with_vm_service(
    nv: &SharedNv,
    manifests: Arc<dyn ManifestProvider>,
    provider: Arc<IvdBankProvider<MemBlockDevice>>,
    vm_service_addr: Option<String>,
) -> ComponentBackend<MemBlockDevice> {
    ComponentBackend::with_options(
        slots::VM1,
        nv.clone(),
        manifests,
        ComponentConfig::default(),
        vm_service_addr,
        None,
        None,
    )
    .with_id("vm1".to_string())
    .with_bank_provider(provider)
}

/// Flash `image` into vm1's target bank through the campaign lifecycle: start,
/// the manifest, the payload (which seals the target), finalize (which
/// activates it).
async fn flash_firmware(b: &ComponentBackend<MemBlockDevice>, image: &[u8]) {
    b.start_flash().await.expect("flash session starts");
    b.receive_package_stream(envelope_stream(firmware_envelope(image)), None)
        .await
        .expect("normal manifest parked");
    b.receive_package_stream(envelope_stream(image.to_vec()), None)
        .await
        .expect("payload staged and the target sealed");
    b.finalize_flash()
        .await
        .expect("finalize activates the flashed bank");
}

#[tokio::test]
async fn campaign_disable_manifest_enacts_at_finalize() {
    // The REAL campaign path: a no-payload disable manifest is parked in
    // AwaitingPayload by the manifest upload (no payload follows), then
    // finalize_flash must ENACT it — deactivate + the sentinel record + record
    // the owed reboot — and return Ok, instead of driving the parked manifest
    // into reconcile (which would hard-error demanding an image_digest a disable
    // lacks). Reverting the finalize enact makes this fail (deactivate never runs).
    let nv = make_nv();
    let tmp = tempfile::tempdir().unwrap();
    installed_gen(&nv, slots::VM1, Bank::A);
    let sel = selector_for(slots::VM1);
    let deact = Arc::new(MockDeactivator::rebooting());
    let (b, provider) = campaign_backend(
        &nv,
        Arc::new(CannedManifest {
            component_name: "vm1".into(),
            disable_target: Some(0),
        }),
        &sel,
        tmp.path(),
    );
    let b = b.with_deactivator(deact.clone());

    assert!(!b.admin_disabled(), "starts enabled");

    // start_flash → manifest upload parks the disable manifest (no payload).
    b.start_flash().await.expect("flash session starts");
    b.receive_package_stream(envelope_stream(detached_envelope()), None)
        .await
        .expect("disable manifest parked");

    // finalize enacts the parked disable instead of reconciling/activating.
    b.finalize_flash()
        .await
        .expect("finalize enacts the disable; no reconcile error");

    // (a) the Deactivator ran; (b) the serving bank holds the sentinel.
    assert_eq!(
        deact.calls(),
        1,
        "deactivate() ran exactly once at finalize"
    );
    assert!(b.admin_disabled(), "admin_disabled() reads the sentinel");
    assert!(
        provider.disabled_record(Bank::A).unwrap().is_some(),
        "the sentinel record is on disk in the serving bank"
    );
    // (c) the owed node reboot is recorded durably (reboot_required deactivator).
    let owed = nv
        .lock()
        .unwrap()
        .read_update_session()
        .map(|s| s.reboot_owed)
        .unwrap_or(0);
    assert_ne!(
        owed & (1u32 << slots::VM1.as_index()),
        0,
        "the disable's owed reboot is recorded in NV"
    );
}

#[tokio::test]
async fn campaign_normal_flash_reenables_by_activating_a_real_ivd() {
    // Companion to the disable test: a NORMAL (non-disable) campaign flash of a
    // currently-disabled component RE-ENABLES it, structurally — the flash seals
    // a real IVD into the target bank and `activate` moves the selector there,
    // so the serving bank reads a real inventory. Nothing clears the sentinel:
    // it stays in the old bank, which is where a rollback would land.
    let nv = make_nv();
    let tmp = tempfile::tempdir().unwrap();
    let sel = selector_for(slots::VM1);
    let deact = Arc::new(MockDeactivator::ok());
    let (b, provider) = campaign_backend(
        &nv,
        Arc::new(CannedManifest {
            component_name: "vm1".into(),
            disable_target: None,
        }),
        &sel,
        tmp.path(),
    );
    let b = b.with_deactivator(deact.clone());

    // Pre-disable it (as a prior disable manifest would have).
    write_sentinel(&provider, &nv, slots::VM1, Bank::A);
    assert!(b.admin_disabled(), "starts disabled");

    // A normal flash through the same lifecycle, its payload streamed in.
    flash_firmware(&b, b"vm1 firmware image").await;

    assert!(
        !b.admin_disabled(),
        "the serving bank now holds a real inventory (re-enabled)"
    );
    assert_eq!(deact.calls(), 0, "re-enable must not run the deactivator");
    let installed = provider
        .read_installed(Bank::B)
        .expect("the target bank is sealed");
    let names: Vec<&str> = installed.files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["firmware"], "the target holds a real IVD");
    assert_eq!(provider.disabled_record(Bank::B).unwrap(), None);
    assert!(
        provider.disabled_record(Bank::A).unwrap().is_some(),
        "the old bank still holds the sentinel"
    );
}

/// Rolling back a re-enable returns the selector to the sentinel bank: the
/// component reads disabled again, and the guest launched for the trial is
/// stopped — the deactivator runs a second time.
#[tokio::test]
async fn rollback_of_reenable_lands_disabled_and_stops_the_guest() {
    let nv = make_nv();
    let tmp = tempfile::tempdir().unwrap();
    installed_gen(&nv, slots::VM1, Bank::A);
    let sel = selector_for(slots::VM1);
    let deact = Arc::new(MockDeactivator::ok());

    // Disabled by a real enact: the sentinel lands in A (deactivator run 1).
    let (disabler, provider) = campaign_backend(
        &nv,
        Arc::new(CannedManifest {
            component_name: "vm1".into(),
            disable_target: Some(0),
        }),
        &sel,
        tmp.path(),
    );
    let disabler = disabler.with_deactivator(deact.clone());
    disabler
        .receive_package(b"disable-envelope")
        .await
        .expect("disable manifest enacted");

    // Re-enabled by a normal flash into B. A second backend over the same bank:
    // the manifest shape is fixed per backend.
    let b = backend_with_manifests(
        &nv,
        slots::VM1,
        "vm1",
        Arc::new(CannedManifest {
            component_name: "vm1".into(),
            disable_target: None,
        }),
    )
    .with_bank_provider(provider.clone())
    .with_deactivator(deact.clone());
    flash_firmware(&b, b"vm1 firmware image").await;
    assert!(!b.admin_disabled(), "the trial bank is a real inventory");

    b.rollback_flash().await.expect("rollback");
    assert!(
        b.admin_disabled(),
        "the rollback lands on the sentinel bank: disabled again"
    );
    assert_eq!(
        deact.calls(),
        2,
        "the trial's guest is stopped: the deactivator ran again"
    );
    let committed =
        nv.lock().unwrap().read_boot_state().unwrap().banks[slots::VM1.as_index()].committed;
    assert!(committed, "rollback must leave the bank set committed");
}

// --- Additional sentinel-record behaviour (F9) ------------------------------
// `non_disableable_component_ignores_sentinel` (no deactivator; a written
// sentinel; admin_disabled() false; /status carries no admin_state) is
// already covered verbatim by `non_disableable_component_omits_admin_state`
// above — skipped here rather than duplicated.

#[tokio::test]
async fn disable_persists_in_bank_ivd_without_selector() {
    // Pre-selector shape: no boot selector wired to the provider at all —
    // `serving_bank()` falls back to `running_bank`. The disable must still
    // persist to the bank's signed IVD and be readable back with no selector
    // in the picture at all.
    let nv = make_nv();
    let tmp = tempfile::tempdir().unwrap();
    installed_gen(&nv, slots::VM1, Bank::A);
    let provider = signing_provider(&nv, slots::VM1, None, tmp.path());
    let b = backend_with_manifests(
        &nv,
        slots::VM1,
        "vm1",
        Arc::new(CannedManifest {
            component_name: "vm1".into(),
            disable_target: Some(0),
        }),
    )
    .with_bank_provider(provider.clone())
    .with_deactivator(Arc::new(MockDeactivator::ok()));

    b.receive_package(b"disable-envelope")
        .await
        .expect("disable manifest enacted");
    assert!(b.admin_disabled(), "disabled with no selector wired");

    // A second backend over the same images_dir/NV, without ever calling
    // enact itself: the sentinel must be durable on disk, not carried in this
    // process's memory.
    let b2 = backend_with_manifests(
        &nv,
        slots::VM1,
        "vm1",
        Arc::new(CannedManifest {
            component_name: "vm1".into(),
            disable_target: None,
        }),
    )
    .with_bank_provider(provider.clone())
    .with_deactivator(Arc::new(MockDeactivator::ok()));
    assert!(
        b2.admin_disabled(),
        "a fresh backend over the same bank reads the persisted sentinel"
    );
}

/// `can_persist_disabled_record()`'s HSM gate must refuse — and the
/// deactivator must never run — for an HSM that exists but was never
/// provisioned, before a single byte of the record is written.
#[tokio::test]
async fn enact_refuses_when_hsm_unprovisioned_before_deactivating() {
    let nv = make_nv();
    let tmp = tempfile::tempdir().unwrap();
    installed_gen(&nv, slots::VM1, Bank::A);

    let ks = tmp.path().join("unprovisioned-keystore");
    std::fs::create_dir_all(&ks).unwrap();
    let hsm: Arc<Mutex<dyn hsm::HsmProvider>> =
        Arc::new(Mutex::new(hsm_sim_backend::SimHsm::new(ks.clone())));
    let provider = Arc::new(
        IvdBankProvider::new(
            nv.clone(),
            slots::VM1,
            false,
            Some(tmp.path().join("images")),
            "vm1".into(),
            Some(hsm),
            None,
            None,
        )
        .with_hsm_crypto(Arc::new(hsm_sim_backend::SimHsm::new(ks))),
    );
    let deact = Arc::new(MockDeactivator::ok());
    let b = backend_with_manifests(
        &nv,
        slots::VM1,
        "vm1",
        Arc::new(CannedManifest {
            component_name: "vm1".into(),
            disable_target: Some(0),
        }),
    )
    .with_bank_provider(provider.clone())
    .with_deactivator(deact.clone());

    let err = b
        .receive_package(b"disable-envelope")
        .await
        .expect_err("an unprovisioned HSM must refuse the disable");
    assert!(
        matches!(err, BackendError::PreconditionFailed(_)),
        "got {err:?}"
    );
    assert_eq!(
        deact.calls(),
        0,
        "the deactivator must not run before the HSM gate"
    );
    let bank_dir = provider.target_bank_dir(Bank::A).unwrap();
    assert!(
        !bank_dir.join(hsm::ivd::IVD_MANIFEST_FILE).exists(),
        "a refused disable writes no IVD manifest"
    );
}

/// A "keyless replay": copy the pre-disable signed IVD pair aside, disable
/// (which ratchets NvFwMeta), then restore the OLD pair over the sentinel.
/// The restored pair is a real, validly-signed inventory — but at the
/// pre-disable gen, one behind the ratcheted NvFwMeta. It must not read as
/// disabled (it is a real inventory, not a sentinel) and it must not pass the
/// launch gate either: replaying old signed bytes cannot forge a bank at the
/// new gen without the signing key.
#[tokio::test]
async fn enact_ratchets_gen_so_the_old_ivd_pair_fails_gen_mismatch() {
    // NOTE: this needs a REAL enact (`receive_package`), not the
    // `write_sentinel` fixture — `write_sentinel` writes the sentinel at
    // whatever gen NvFwMeta ALREADY holds (it doesn't ratchet), so it cannot
    // exercise "the old pair now fails at the ratcheted gen".
    let nv = make_nv();
    let tmp = tempfile::tempdir().unwrap();
    let old_gen = installed_gen(&nv, slots::VM1, Bank::A);
    let provider = signing_provider(&nv, slots::VM1, None, tmp.path());

    // Seal a real inventory at the pre-disable gen — what the bank held
    // before the disable.
    let bank_dir = provider.target_bank_dir(Bank::A).unwrap();
    std::fs::create_dir_all(&bank_dir).unwrap();
    std::fs::write(bank_dir.join("kernel"), b"kernel bytes").unwrap();
    provider
        .seal(
            Bank::A,
            FirmwareIdentity::default(),
            old_gen,
            &["kernel".to_string()],
        )
        .unwrap();
    let old_manifest = std::fs::read(bank_dir.join(hsm::ivd::IVD_MANIFEST_FILE)).unwrap();
    let old_signature = std::fs::read(bank_dir.join(hsm::ivd::IVD_SIGNATURE_FILE)).unwrap();

    // A real enact: ratchets NvFwMeta from old_gen to old_gen + 1 and signs
    // the sentinel there. Checked via the PROVIDER, not `b.admin_disabled()`:
    // the backend caches its answer per serving bank until an NV write
    // clears it, and the replay below is a raw file swap with no NV write —
    // calling `b.admin_disabled()` here would poison that cache with
    // "disabled" and the assertion below would pass for the wrong reason.
    let b = backend_with_manifests(
        &nv,
        slots::VM1,
        "vm1",
        Arc::new(CannedManifest {
            component_name: "vm1".into(),
            disable_target: Some(0),
        }),
    )
    .with_bank_provider(provider.clone())
    .with_deactivator(Arc::new(MockDeactivator::ok()));
    b.receive_package(b"disable-envelope")
        .await
        .expect("disable manifest enacted");
    assert_eq!(
        provider.disabled_record(Bank::A).unwrap(),
        Some(old_gen + 1),
        "precondition: the sentinel verifies at the ratcheted gen"
    );

    // The replay: restore the old (pre-disable) pair over the sentinel.
    std::fs::write(bank_dir.join(hsm::ivd::IVD_MANIFEST_FILE), &old_manifest).unwrap();
    std::fs::write(bank_dir.join(hsm::ivd::IVD_SIGNATURE_FILE), &old_signature).unwrap();

    assert!(
        !b.admin_disabled(),
        "the restored pair is a real inventory, not a sentinel — a replay does not re-enable"
    );

    let new_gen = nv
        .lock()
        .unwrap()
        .read_fw_meta(slots::VM1, Bank::A)
        .unwrap()
        .gen;
    assert_eq!(new_gen, old_gen + 1, "precondition: gen was ratcheted");
    let crypto = hsm_sim_backend::SimHsm::new(tmp.path().join("keystore"));
    let pins = hsm::ivd::VerifyPins {
        expected_install_gen: Some(new_gen),
        min_committed_gen: None,
    };
    match hsm::ivd::verify_bank_crypto(&crypto, &bank_dir, pins) {
        Err(hsm::ivd::IvdError::GenMismatch { expected, claimed }) => {
            assert_eq!(expected, new_gen);
            assert_eq!(claimed, old_gen);
        }
        other => panic!("expected GenMismatch, got {other:?}"),
    }
}

/// A sentinel manifest with a bad signature (structurally well-formed — a
/// real signature with one flipped byte, `disable_record_tests.rs`'s "bad
/// signature" shape — not arbitrary garbage bytes, which the crypto backend
/// refuses to even parse and which would test the wrong failure mode) must
/// not read as disabled, and the launch-time verify must refuse it as a bad
/// signature — never confuse it with a real `AdminDisabled` sentinel, which
/// requires a signature that actually verifies.
#[tokio::test]
async fn unsigned_sentinel_reads_enabled_and_verify_refuses() {
    let nv = make_nv();
    let tmp = tempfile::tempdir().unwrap();
    let (b, provider) =
        vm_backend_with_selector(&nv, slots::VM1, None, selector_for(slots::VM1), tmp.path());
    let b = b.with_deactivator(Arc::new(MockDeactivator::ok()));
    let gen = installed_gen(&nv, slots::VM1, Bank::A);
    // A real, validly-signed sentinel first — `b.admin_disabled()` is not
    // called yet, so its per-bank cache stays cold; the first call below
    // derives fresh from the (about to be corrupted) on-disk state.
    write_sentinel(&provider, &nv, slots::VM1, Bank::A);

    let bank_dir = provider.target_bank_dir(Bank::A).unwrap();
    let sig_path = bank_dir.join(hsm::ivd::IVD_SIGNATURE_FILE);
    let mut sig = std::fs::read(&sig_path).unwrap();
    let last = sig.len() - 1;
    sig[last] ^= 0x01;
    std::fs::write(&sig_path, &sig).unwrap();

    assert!(
        !b.admin_disabled(),
        "a bad-signature sentinel must not read as disabled"
    );

    let crypto = hsm_sim_backend::SimHsm::new(tmp.path().join("keystore"));
    let pins = hsm::ivd::VerifyPins {
        expected_install_gen: Some(gen),
        min_committed_gen: None,
    };
    match hsm::ivd::verify_bank_crypto(&crypto, &bank_dir, pins) {
        Err(hsm::ivd::IvdError::SignatureInvalid) => {}
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }
}

#[tokio::test]
async fn reenable_flash_reads_enabled_before_ecu_reset_and_relaunches_once() {
    let nv = make_nv();
    let tmp = tempfile::tempdir().unwrap();
    installed_gen(&nv, slots::VM1, Bank::A);
    let sel = selector_for(slots::VM1);
    let (addr, hits) = counting_post_server().await;
    let deact = Arc::new(MockDeactivator::ok());

    // Disabled via the real SUIT disable-manifest path.
    let (disabler, provider) = campaign_backend(
        &nv,
        Arc::new(CannedManifest {
            component_name: "vm1".into(),
            disable_target: Some(0),
        }),
        &sel,
        tmp.path(),
    );
    let disabler = disabler.with_deactivator(deact.clone());
    disabler
        .receive_package(b"disable-envelope")
        .await
        .expect("disable manifest enacted");

    // A second backend (the manifest shape is fixed per backend), wired to
    // vm-service, drives the re-enabling flash and the reset.
    let b = campaign_backend_with_vm_service(
        &nv,
        Arc::new(CannedManifest {
            component_name: "vm1".into(),
            disable_target: None,
        }),
        provider.clone(),
        Some(addr),
    )
    .with_deactivator(deact.clone());
    assert!(b.admin_disabled(), "starts disabled");

    flash_firmware(&b, b"vm1 firmware image").await;
    assert!(
        !b.admin_disabled(),
        "the flash must re-enable before any reset is issued"
    );

    b.ecu_reset(0x01).await.unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "exactly one vm-service relaunch after the re-enabling flash"
    );
}

/// Mirrors production construction order (`component_factory::build_component`
/// wires a fresh `ComponentBackend` + selector-aware `IvdBankProvider` over
/// the same on-disk dirs at every process start) without taking a dependency
/// on the component-factory crate itself. The property under test:
/// `read_entity_status()`'s FIRST call on a brand-new backend — no NV write
/// has happened in this process to warm any cache — reads the persisted
/// sentinel straight off disk.
#[tokio::test]
async fn startup_with_existing_sentinel_reports_disabled_before_any_nv_write() {
    let nv = make_nv();
    let tmp = tempfile::tempdir().unwrap();
    let sel = selector_for(slots::VM1);
    installed_gen(&nv, slots::VM1, Bank::A);
    let provider = signing_provider(&nv, slots::VM1, Some(sel), tmp.path());
    let b = backend_with_manifests(
        &nv,
        slots::VM1,
        "vm1",
        Arc::new(CannedManifest {
            component_name: "vm1".into(),
            disable_target: Some(0),
        }),
    )
    .with_bank_provider(provider.clone())
    .with_deactivator(Arc::new(MockDeactivator::ok()));
    b.receive_package(b"disable-envelope")
        .await
        .expect("disable manifest enacted");
    drop(b);

    // A brand-new backend instance over the same nv/provider — no shared
    // in-memory cache with the one that enacted the disable.
    let fresh = vm_backend(&nv, slots::VM1, None)
        .with_bank_provider(provider.clone())
        .with_deactivator(Arc::new(MockDeactivator::ok()));

    let status = fresh.read_entity_status().await.unwrap();
    assert_eq!(
        status.extensions["x-runtime"]["admin_state"], "disabled",
        "the first read on a fresh backend must see the persisted sentinel"
    );
}

/// After enact, `x-ota-installed-manifest` reports the sentinel: exactly one
/// file (the reserved `.admin-disabled` path, all-zero digest) and the
/// identity strings carried over from the pre-disable manifest.
#[tokio::test]
async fn installed_manifest_shows_sentinel_when_disabled() {
    let nv = make_nv();
    let tmp = tempfile::tempdir().unwrap();
    let (b, provider) =
        vm_backend_with_selector(&nv, slots::VM1, None, selector_for(slots::VM1), tmp.path());
    let b = b.with_deactivator(Arc::new(MockDeactivator::ok()));
    let gen = installed_gen(&nv, slots::VM1, Bank::A);

    // Seal a real, identified inventory first — the disable must carry this
    // identity forward into the sentinel.
    let bank_dir = provider.target_bank_dir(Bank::A).unwrap();
    std::fs::create_dir_all(&bank_dir).unwrap();
    std::fs::write(bank_dir.join("kernel"), b"kernel bytes").unwrap();
    provider
        .seal(
            Bank::A,
            FirmwareIdentity {
                version: Some("1.2.0".into()),
                ecu_sw_number: Some("VM1-SW-001".into()),
                ..Default::default()
            },
            gen,
            &["kernel".to_string()],
        )
        .unwrap();

    write_sentinel(&provider, &nv, slots::VM1, Bank::A);
    assert!(b.admin_disabled(), "precondition: disabled");

    let vals = b
        .read_data(&[INSTALLED_MANIFEST_PARAM_ID.to_string()])
        .await
        .expect("x-ota-installed-manifest reads even when disabled");
    let v = &vals[0].value;
    let files = v["files"].as_array().expect("files array");
    assert_eq!(
        files.len(),
        1,
        "the sentinel inventory is exactly one file: {files:?}"
    );
    assert_eq!(files[0]["path"], hsm::ivd::IVD_DISABLED_RECORD_PATH);
    let zero_sha = "0".repeat(64);
    assert_eq!(
        files[0]["sha256"].as_str().unwrap(),
        zero_sha,
        "the sentinel digest is 32 zero bytes: {files:?}"
    );
    assert_eq!(v["identity"]["version"], "1.2.0");
    assert_eq!(v["identity"]["ecu_sw_number"], "VM1-SW-001");
}

// --- Single-bank (rt-shaped) sentinel behaviour -----------------------------

#[tokio::test]
async fn single_bank_rt_abort_keeps_the_sentinel() {
    let nv = make_nv();
    let tmp = tempfile::tempdir().unwrap();
    let sel = selector_for(slots::RT);
    let provider = single_bank_signing_provider(&nv, slots::RT, "rt", Some(sel), tmp.path());
    let b = rt_backend_with_manifests(&nv, Arc::new(StubManifests), provider.clone())
        .with_deactivator(Arc::new(MockDeactivator::ok()));

    write_sentinel(&provider, &nv, slots::RT, Bank::A);
    assert!(b.admin_disabled(), "precondition: disabled");

    b.start_flash().await.expect("flash session starts");
    b.abort_flash("t1").await.expect("abort clears the session");

    assert!(b.admin_disabled(), "abort must not clear the sentinel");
    let bank_a = provider.target_bank_dir(Bank::A).unwrap();
    assert!(
        bank_a.join(hsm::ivd::IVD_MANIFEST_FILE).exists(),
        "the sentinel manifest must survive an abort"
    );
    assert!(
        bank_a.join(hsm::ivd::IVD_SIGNATURE_FILE).exists(),
        "the sentinel signature must survive an abort"
    );
}

/// Companion to the abort test: a normal single-shot flash of a real payload
/// (not an abort) DOES replace the sentinel — re-enabling structurally, same
/// as the banked `campaign_normal_flash_reenables_by_activating_a_real_ivd`.
#[tokio::test]
async fn single_bank_rt_disable_then_reenable() {
    let nv = make_nv();
    let tmp = tempfile::tempdir().unwrap();
    installed_gen(&nv, slots::RT, Bank::A);
    let sel = selector_for(slots::RT);
    let provider = single_bank_signing_provider(&nv, slots::RT, "rt", Some(sel), tmp.path());
    let deact = Arc::new(MockDeactivator::ok());

    let disabler = rt_backend_with_manifests(
        &nv,
        Arc::new(CannedManifest {
            component_name: "rt".into(),
            disable_target: Some(0),
        }),
        provider.clone(),
    )
    .with_deactivator(deact.clone());
    disabler
        .receive_package(b"disable-envelope")
        .await
        .expect("disable manifest enacted");
    assert!(disabler.admin_disabled(), "starts disabled");

    let reenabler = rt_backend_with_manifests(
        &nv,
        Arc::new(CannedManifest {
            component_name: "rt".into(),
            disable_target: None,
        }),
        provider.clone(),
    )
    .with_deactivator(deact.clone());
    flash_firmware(&reenabler, b"rt firmware image").await;

    assert!(
        !reenabler.admin_disabled(),
        "a normal single-shot flash re-enables the single-bank component"
    );
    assert_eq!(
        deact.calls(),
        1,
        "re-enable must not run the deactivator again"
    );
}
