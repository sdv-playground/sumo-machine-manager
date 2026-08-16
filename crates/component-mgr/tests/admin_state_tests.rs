//! Integration tests for the per-component administrative state slice: the
//! SUIT disable-manifest enact path (`enact_disable_manifest`), the signed
//! selector as the disable authority (`admin_disabled`), and the flash-gate +
//! status + reset enforcement points — mirroring the `sovd_tests.rs` harness
//! style.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use nv_store::block::MemBlockDevice;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::*;

use machine_mgr::{
    DeactivateError, DeactivateOutcome, Deactivator, InMemorySelectorStore, SharedSystemBankState,
    SystemBankManager, TestSigner,
};
use sovd_core::{BackendError, DiagnosticBackend, EntityStatus, PackageStream};

use component_mgr::backend::{ComponentBackend, ComponentConfig};
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
    bank_set: BankSet,
    disable_target: Option<usize>,
}
impl ManifestProvider for CannedManifest {
    fn validate(&self, _data: &[u8], _min: u32) -> Result<ValidatedFirmware, ManifestError> {
        Ok(ValidatedFirmware {
            bank_set: self.bank_set,
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
}

/// A shared boot selector with a booted selection for `set` (so the provider
/// resolves a bank); the disable set starts empty. The signed selector is the
/// read/write authority for a component's administrative disable state.
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

/// Set/clear `set`'s disable bit in the selector directly — the state a SUIT
/// disable manifest (`record_disabled`) persists and `admin_disabled()` reads.
fn set_selector_disabled(sel: &SharedSystemBankState, set: BankSet, disabled: bool) {
    sel.write().unwrap().stage_disabled(set, disabled);
}

/// A vm-style backend whose bank provider is wired to `selector`, so the
/// disable read/write paths route through it (the production shape once the
/// signed selector is the disable authority).
fn vm_backend_with_selector(
    nv: &SharedNv,
    set: BankSet,
    vm_service_addr: Option<String>,
    selector: SharedSystemBankState,
) -> ComponentBackend<MemBlockDevice> {
    let provider = IvdBankProvider::new(
        nv.clone(),
        set,
        false,
        None,
        "disable".into(),
        None,
        None,
        Some(selector),
    );
    vm_backend(nv, set, vm_service_addr).with_bank_provider(Arc::new(provider))
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

// --- Backend semantics -----------------------------------------------------

#[tokio::test]
async fn non_disableable_component_omits_admin_state() {
    // No deactivator ⇒ not disableable. `admin_disabled()` short-circuits on
    // `is_disableable()`, so even a disable bit set in the signed selector reads
    // as enabled — the equipped deactivator is the authority.
    let nv = make_nv();
    let sel = selector_for(BankSet::Vm1);
    let b = vm_backend_with_selector(&nv, BankSet::Vm1, None, sel.clone());
    assert!(!b.is_disableable());

    set_selector_disabled(&sel, BankSet::Vm1, true);
    assert!(
        !b.admin_disabled(),
        "a disable bit on a non-disableable component reads as enabled"
    );

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
async fn ensure_flash_can_start_admits_disabled() {
    // E4a relaxed the gate: a disabled component is NO LONGER refused here — the
    // real-flash paths clear its disable bit at admission (re-enable on flash),
    // so the gate must admit it. The "disabled ⇒ never uncommitted" invariant is
    // preserved by clearing before trial, not by refusing at this gate.
    let nv = make_nv();
    let sel = selector_for(BankSet::Vm1);
    let b = vm_backend_with_selector(&nv, BankSet::Vm1, None, sel.clone())
        .with_deactivator(Arc::new(MockDeactivator::ok()));
    b.ensure_flash_can_start()
        .expect("enabled component is flashable");

    set_selector_disabled(&sel, BankSet::Vm1, true);
    b.ensure_flash_can_start()
        .expect("a disabled component is now admitted (re-enabled at flash admission)");
}

#[tokio::test]
async fn read_entity_status_tri_state_and_probe_skip() {
    let nv = make_nv();
    let (addr, probes) = counting_server().await;
    let sel = selector_for(BankSet::Vm1);
    let b = vm_backend_with_selector(&nv, BankSet::Vm1, Some(addr), sel.clone())
        .with_deactivator(Arc::new(MockDeactivator::ok()));

    // Disabled: NotReady, admin_state "disabled", and the vm-service probe
    // is SKIPPED (zero connections — no phantom health traffic to a VM that
    // is down by design).
    set_selector_disabled(&sel, BankSet::Vm1, true);
    let status = b.read_entity_status().await.unwrap();
    assert_eq!(status.status, EntityStatus::NotReady);
    assert_eq!(
        status.extensions["x-sumo-runtime"]["admin_state"], "disabled",
        "disabled read-back"
    );
    assert_eq!(probes.load(Ordering::SeqCst), 0, "probe must be skipped");

    // Enabled again: the probe runs (our canned server is not a healthy
    // guest, so spec status stays notReady — honesty), admin_state "enabled".
    set_selector_disabled(&sel, BankSet::Vm1, false);
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
    let sel = selector_for(BankSet::Rt);
    let b = vm_backend_with_selector(&nv, BankSet::Rt, None, sel.clone())
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
    set_selector_disabled(&sel, BankSet::Rt, true);
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
    let sel2 = selector_for(BankSet::Rt);
    let b = vm_backend_with_selector(&nv2, BankSet::Rt, None, sel2.clone())
        .with_deactivator(Arc::new(MockDeactivator::ok()))
        .with_health_probe(Arc::new(MockProbe { running: true }));
    set_selector_disabled(&sel2, BankSet::Rt, true);
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
    let sel = selector_for(BankSet::Vm1);
    let b = vm_backend_with_selector(&nv, BankSet::Vm1, Some(addr), sel.clone())
        .with_deactivator(Arc::new(MockDeactivator::ok()));

    // Disabled: a reset must NOT resurrect the VM — zero vm-service traffic
    // (neither the was-running probe nor the start/restart notify).
    set_selector_disabled(&sel, BankSet::Vm1, true);
    b.ecu_reset(0x01).await.unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "reset of a disabled component must not touch vm-service"
    );

    // Enabled: the reset notifies vm-service again.
    set_selector_disabled(&sel, BankSet::Vm1, false);
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
    let deact = Arc::new(MockDeactivator::rebooting());
    let b = backend_with_manifests(
        &nv,
        BankSet::Vm1,
        Arc::new(CannedManifest {
            bank_set: BankSet::Vm1,
            disable_target: Some(0),
        }),
    )
    .with_deactivator(deact.clone());

    // Routes to the deactivator (not stored as a package); reboot_required=true
    // is handled (captured, non-fatal).
    b.receive_package(b"disable-envelope")
        .await
        .expect("disable manifest enacted");
    assert_eq!(deact.calls(), 1, "deactivate() invoked exactly once");
}

#[tokio::test]
async fn suit_disable_manifest_writes_selector_and_start_flash_admits_without_clearing() {
    // A SUIT disable manifest on the single-shot `receive_package` path routes to
    // `enact_disable_manifest`, which persists the disable in the signed selector
    // (`record_disabled(true)`); `admin_disabled()` reads it back. Re-enable has
    // MOVED off flash admission: `start_flash` now admits a disabled component but
    // no longer clears the selector — that clear happens at `finalize_flash`,
    // before trial (see `campaign_normal_flash_reenables_at_finalize`).
    let nv = make_nv();
    let sel = selector_for(BankSet::Vm1);
    let deact = Arc::new(MockDeactivator::ok());
    let b = backend_with_manifests(
        &nv,
        BankSet::Vm1,
        Arc::new(CannedManifest {
            bank_set: BankSet::Vm1,
            disable_target: Some(0),
        }),
    )
    .with_deactivator(deact.clone())
    .with_bank_provider(Arc::new(IvdBankProvider::new(
        nv.clone(),
        BankSet::Vm1,
        false,
        None,
        "vm1".into(),
        None,
        None,
        Some(sel.clone()),
    )));

    assert!(!b.admin_disabled(), "starts enabled");
    assert!(!sel.read().unwrap().disabled(BankSet::Vm1));

    // Disable via the SUIT manifest → deactivate + record_disabled(true).
    b.receive_package(b"disable-envelope")
        .await
        .expect("disable manifest enacted");
    assert_eq!(deact.calls(), 1, "deactivator enacted once");
    assert!(
        sel.read().unwrap().disabled(BankSet::Vm1),
        "the disable is persisted in the signed selector"
    );
    assert!(b.admin_disabled(), "admin_disabled() reads the selector");

    // Re-enable moved OUT of flash admission: `start_flash` now ADMITS a disabled
    // component (the gate is relaxed) but no longer clears the selector — the
    // re-enable clear happens at `finalize_flash`, before trial. So the disable
    // bit is still set right after admission.
    b.start_flash()
        .await
        .expect("start_flash admits a disabled component");
    assert!(
        sel.read().unwrap().disabled(BankSet::Vm1),
        "start_flash no longer clears the disable bit — that moved to finalize"
    );
    assert!(
        b.admin_disabled(),
        "still disabled until finalize re-enables"
    );
}

#[tokio::test]
async fn non_disable_no_payload_manifest_is_a_noop() {
    let nv = make_nv();
    let deact = Arc::new(MockDeactivator::ok());
    let b = backend_with_manifests(
        &nv,
        BankSet::Vm1,
        Arc::new(CannedManifest {
            bank_set: BankSet::Vm1,
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
        BankSet::Vm1,
        Arc::new(CannedManifest {
            bank_set: BankSet::Vm1,
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
    let deact = Arc::new(MockDeactivator::failing());
    let b = backend_with_manifests(
        &nv,
        BankSet::Vm1,
        Arc::new(CannedManifest {
            bank_set: BankSet::Vm1,
            disable_target: Some(0),
        }),
    )
    .with_deactivator(deact.clone());
    let err = b
        .receive_package(b"disable-envelope")
        .await
        .expect_err("a failing deactivator must surface an error");
    assert_eq!(deact.calls(), 1);
    assert!(matches!(err, BackendError::Internal(_)), "got {err:?}");
}

#[tokio::test]
async fn disable_manifest_for_other_component_is_rejected_before_enact() {
    let nv = make_nv();
    let deact = Arc::new(MockDeactivator::ok());
    // Manifest names Vm2 but is POSTed to the Vm1 backend — the existing
    // bank_set guard rejects it before any enact (no cross-component dispatch).
    let b = backend_with_manifests(
        &nv,
        BankSet::Vm1,
        Arc::new(CannedManifest {
            bank_set: BankSet::Vm2,
            disable_target: Some(0),
        }),
    )
    .with_deactivator(deact.clone());
    let err = b
        .receive_package(b"disable-envelope")
        .await
        .expect_err("cross-component disable must be rejected");
    assert!(
        matches!(err, BackendError::InvalidRequest(_)),
        "got {err:?}"
    );
    assert_eq!(
        deact.calls(),
        0,
        "deactivator must not run on a bank_set mismatch"
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

/// Wrap envelope bytes as the single-chunk `PackageStream` the upload path reads.
fn envelope_stream(data: Vec<u8>) -> PackageStream {
    Box::pin(futures::stream::iter(vec![Ok::<
        bytes::Bytes,
        Box<dyn std::error::Error + Send + Sync>,
    >(bytes::Bytes::from(data))]))
}

/// A vm1 backend wired with `CannedManifest` (so the campaign manifest upload
/// validates to the desired disable/normal shape) AND a selector-backed provider
/// (so `record_disabled` writes/reads the shared selector `sel`).
fn campaign_backend(
    nv: &SharedNv,
    manifests: Arc<dyn ManifestProvider>,
    sel: &SharedSystemBankState,
) -> ComponentBackend<MemBlockDevice> {
    backend_with_manifests(nv, BankSet::Vm1, manifests).with_bank_provider(Arc::new(
        IvdBankProvider::new(
            nv.clone(),
            BankSet::Vm1,
            false,
            None,
            "vm1".into(),
            None,
            None,
            Some(sel.clone()),
        ),
    ))
}

#[tokio::test]
async fn campaign_disable_manifest_enacts_at_finalize() {
    // The REAL campaign path: a no-payload disable manifest is parked in
    // AwaitingPayload by the manifest upload (no payload follows), then
    // finalize_flash must ENACT it — deactivate + record_disabled(true) + record
    // the owed reboot — and return Ok, instead of driving the parked manifest
    // into reconcile (which would hard-error demanding an image_digest a disable
    // lacks). Reverting the finalize enact makes this fail (deactivate never runs).
    let nv = make_nv();
    let sel = selector_for(BankSet::Vm1);
    let deact = Arc::new(MockDeactivator::rebooting());
    let b = campaign_backend(
        &nv,
        Arc::new(CannedManifest {
            bank_set: BankSet::Vm1,
            disable_target: Some(0),
        }),
        &sel,
    )
    .with_deactivator(deact.clone());

    assert!(
        !sel.read().unwrap().disabled(BankSet::Vm1),
        "starts enabled"
    );

    // start_flash → manifest upload parks the disable manifest (no payload).
    b.start_flash().await.expect("flash session starts");
    b.receive_package_stream(envelope_stream(detached_envelope()), None)
        .await
        .expect("disable manifest parked");

    // finalize enacts the parked disable instead of reconciling/activating.
    b.finalize_flash()
        .await
        .expect("finalize enacts the disable; no reconcile error");

    // (a) the Deactivator ran; (b) the selector records the disable.
    assert_eq!(
        deact.calls(),
        1,
        "deactivate() ran exactly once at finalize"
    );
    assert!(
        sel.read().unwrap().disabled(BankSet::Vm1),
        "record_disabled(true) persisted in the signed selector"
    );
    // (c) the owed node reboot is recorded durably (reboot_required deactivator).
    let owed = nv
        .lock()
        .unwrap()
        .read_update_session()
        .map(|s| s.reboot_owed)
        .unwrap_or(0);
    assert_ne!(
        owed & (1u16 << BankSet::Vm1.as_index()),
        0,
        "the disable's owed reboot is recorded in NV"
    );
}

#[tokio::test]
async fn campaign_normal_flash_reenables_at_finalize() {
    // Companion to the disable test: a NORMAL (non-disable) campaign flash of a
    // currently-disabled component RE-ENABLES it — finalize_flash clears the
    // selector's disable bit before trial, the SUIT-native replacement for the
    // manual enable lever now that the mis-placed start_flash clear is gone.
    let nv = make_nv();
    let sel = selector_for(BankSet::Vm1);
    let deact = Arc::new(MockDeactivator::ok());
    let b = campaign_backend(
        &nv,
        Arc::new(CannedManifest {
            bank_set: BankSet::Vm1,
            disable_target: None,
        }),
        &sel,
    )
    .with_deactivator(deact.clone());

    // Pre-disable it (as a prior disable manifest would have).
    set_selector_disabled(&sel, BankSet::Vm1, true);
    assert!(
        sel.read().unwrap().disabled(BankSet::Vm1),
        "starts disabled"
    );

    // A normal flash through the same lifecycle.
    b.start_flash().await.expect("flash session starts");
    b.receive_package_stream(envelope_stream(detached_envelope()), None)
        .await
        .expect("normal manifest parked");
    b.finalize_flash()
        .await
        .expect("finalize re-enables + activates");

    assert!(
        !sel.read().unwrap().disabled(BankSet::Vm1),
        "finalize cleared the selector's disable bit (re-enabled)"
    );
    assert_eq!(deact.calls(), 0, "re-enable must not run the deactivator");
}
