//! Tests for `InstallRouterDiag` — the vm2 install-time routing wrapper.
//!
//! Two concerns:
//!
//! 1. **Install routing through the router** — a container-image SUIT manifest
//!    drives the container path; a VM SUIT manifest drives the VM path. Proven
//!    with spy `Component`s wired into a real `AppInstallRouterComponent`,
//!    driven through the `DiagnosticBackend` (SOVD) wire.
//! 2. **Delegation to the engine** — a data read and a fault read go straight
//!    to the `ComponentBackend` engine and return real values (not
//!    `ParameterNotFound` / error), proving the wrapper doesn't re-implement
//!    (and break) the data path the way the retired `ComponentDiagBackend` did.
//!    A factory DID (`serial_number`, NV-seeded) gives a concrete real value
//!    without needing a signed manifest; `fw_version` is asserted to delegate
//!    *identically* to the engine (wrapper result == engine result), so the
//!    wrapper adds no divergent data behavior of its own.
//!
//! The data/faults/modes "routes through Component" coverage that used to live
//! here is dropped — `backend.rs` already owns those tests against the single
//! authority.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use machine_mgr::{
    Capabilities, Component, EnvelopeStream, FlashCaps, FlashId, FlashSession, LifecycleCaps,
    MachineError, MachineResult, ResetKind,
};

use sovd_core::DiagnosticBackend;

use nv_store::block::MemBlockDevice;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::*;

use sumo_offboard::keygen::{self, ES256};
use sumo_offboard::ImageManifestBuilder;

use component_mgr::app_install_router::AppInstallRouterComponent;
use component_mgr::backend::{ComponentBackend, ComponentConfig};
use component_mgr::install_router_diag::InstallRouterDiag;
use component_mgr::manifest_provider::{
    ManifestError, ManifestProvider, ManifestType, ValidatedFirmware,
};
use component_mgr::ota::ImageMeta;
use component_mgr::suit_provider::SuitProvider;

// ---------------------------------------------------------------------------
// Install-routing tests: container-vs-VM through the real router
// ---------------------------------------------------------------------------

/// Spy `Component` that records the bytes it received on `upload_envelope`, so
/// a test can prove which install route (VM vs container) the router selected.
struct UploadSpy {
    id: &'static str,
    bytes_seen: Arc<AtomicUsize>,
    capabilities: Capabilities,
}

impl UploadSpy {
    fn new(id: &'static str) -> Self {
        Self {
            id,
            bytes_seen: Arc::new(AtomicUsize::new(0)),
            capabilities: Capabilities {
                did_store: false,
                flash: Some(FlashCaps {
                    dual_bank: false,
                    supports_rollback: false,
                    supports_trial_boot: false,
                    abortable_after_finalize: false,
                    reset_kind: ResetKind::Local,
                }),
                lifecycle: Some(LifecycleCaps {
                    restartable: false,
                    has_runtime_state: false,
                }),
                hsm: None,
                dtcs: false,
                clear_dtcs: false,
            },
        }
    }
}

#[async_trait]
impl Component for UploadSpy {
    fn id(&self) -> &str {
        self.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    async fn authorize_install(&self) -> MachineResult<()> {
        Ok(())
    }

    async fn start_install(&self) -> MachineResult<FlashSession> {
        Ok(FlashSession {
            id: FlashId::new(self.id),
            target_bank: None,
            max_chunk_size: 0,
        })
    }

    async fn upload_envelope(
        &self,
        _id: &FlashId,
        mut stream: EnvelopeStream,
    ) -> MachineResult<String> {
        use futures::StreamExt;
        let mut total = 0usize;
        while let Some(chunk) = stream.next().await {
            let b = chunk.map_err(|e| MachineError::Internal(e.to_string()))?;
            total += b.len();
        }
        self.bytes_seen.store(total, Ordering::SeqCst);
        Ok(format!("{}-upload", self.id))
    }
}

/// Accepts any manifest as a valid container-image (header-only) manifest, so
/// the router takes the container path when the component-id matches.
struct AcceptingManifestProvider;

impl ManifestProvider for AcceptingManifestProvider {
    fn validate(
        &self,
        _data: &[u8],
        _min_security_ver: u32,
    ) -> Result<ValidatedFirmware, ManifestError> {
        Ok(ValidatedFirmware {
            bank_set: BankSet::Vm2,
            manifest_type: ManifestType::Firmware,
            image_meta: ImageMeta::default(),
            image_data: Vec::new(),
            version_display: "1.0.0".into(),
            image_sha256: None,
            image_size: None,
            raw_envelope: None,
            streamed_files: Vec::new(),
            signing_time_secs: None,
            disable_target: None,
        })
    }
}

fn engine_backend() -> Arc<ComponentBackend<MemBlockDevice>> {
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    nv.write_boot_state(&mut NvBootState::default()).unwrap();
    let nv = Arc::new(Mutex::new(nv));

    let mp: Arc<dyn ManifestProvider> = Arc::new(SuitProvider::new(vec![0u8; 32]));
    Arc::new(ComponentBackend::new(
        BankSet::Vm2,
        nv,
        mp,
        ComponentConfig::default(),
    ))
}

fn container_image_manifest() -> Vec<u8> {
    let signing_key = keygen::generate_signing_key(ES256).unwrap();
    ImageManifestBuilder::new()
        .signing_time(1_700_000_000)
        .component_id(vec!["vm2".into(), "container_image".into()])
        .sequence_number(1)
        .payload_digest(&[0u8; 32], 0)
        .payload_uri("#container-image".into())
        .security_version(1)
        .build(&signing_key)
        .unwrap()
}

fn vm_manifest() -> Vec<u8> {
    let signing_key = keygen::generate_signing_key(ES256).unwrap();
    ImageManifestBuilder::new()
        .signing_time(1_700_000_000)
        // A plain VM component id (not [vm2, container_image]) → VM path.
        .component_id(vec!["vm2".into()])
        .sequence_number(1)
        .payload_digest(&[0u8; 32], 0)
        .payload_uri("#kernel".into())
        .security_version(1)
        .build(&signing_key)
        .unwrap()
}

/// A container-image manifest (component-id `[vm2, container_image]`) routes
/// the upload through the container path — proven by the container spy seeing
/// the bytes and the VM spy seeing none.
#[tokio::test]
async fn container_manifest_routes_to_container_path() {
    let vm = Arc::new(UploadSpy::new("vm2"));
    let container = Arc::new(UploadSpy::new("container_image"));
    let vm_bytes = vm.bytes_seen.clone();
    let container_bytes = container.bytes_seen.clone();

    let router: Arc<dyn Component> = Arc::new(AppInstallRouterComponent::new(
        "vm2",
        vm,
        container,
        Arc::new(AcceptingManifestProvider),
    ));
    let diag = InstallRouterDiag::new(router, engine_backend());

    diag.start_flash().await.unwrap();
    let manifest = container_image_manifest();
    let expected_len = manifest.len();
    let upload_id = diag.receive_package(&manifest).await.unwrap();

    assert_eq!(upload_id, "container_image-upload");
    assert_eq!(container_bytes.load(Ordering::SeqCst), expected_len);
    assert_eq!(vm_bytes.load(Ordering::SeqCst), 0);
}

/// A plain VM manifest (component-id `[vm2]`) routes the upload through the VM
/// path — proven by the VM spy seeing the bytes and the container spy none.
#[tokio::test]
async fn vm_manifest_routes_to_vm_path() {
    let vm = Arc::new(UploadSpy::new("vm2"));
    let container = Arc::new(UploadSpy::new("container_image"));
    let vm_bytes = vm.bytes_seen.clone();
    let container_bytes = container.bytes_seen.clone();

    let router: Arc<dyn Component> = Arc::new(AppInstallRouterComponent::new(
        "vm2",
        vm,
        container,
        Arc::new(AcceptingManifestProvider),
    ));
    let diag = InstallRouterDiag::new(router, engine_backend());

    diag.start_flash().await.unwrap();
    let manifest = vm_manifest();
    let expected_len = manifest.len();
    let upload_id = diag.receive_package(&manifest).await.unwrap();

    assert_eq!(upload_id, "vm2-upload");
    assert_eq!(vm_bytes.load(Ordering::SeqCst), expected_len);
    assert_eq!(container_bytes.load(Ordering::SeqCst), 0);
}

// ---------------------------------------------------------------------------
// Delegation tests: non-install methods reach the engine and return real data
// ---------------------------------------------------------------------------

/// Build an `InstallRouterDiag` whose VM side is a real `ComponentBackend`
/// (the engine) seeded with factory data (so `serial_number` reads back a real
/// value). Returns `(diag, engine)` — the engine handle lets a test compare
/// wrapper-vs-engine for parity. Uses only the public `ComponentBackend` API,
/// so it doesn't reach into `backend.rs` internals.
fn router_diag_with_factory(
    serial: &str,
) -> (InstallRouterDiag, Arc<ComponentBackend<MemBlockDevice>>) {
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    nv.write_boot_state(&mut NvBootState::default()).unwrap();

    let mut f = NvFactory::default();
    let n = serial.len().min(f.serial_number.len());
    f.serial_number[..n].copy_from_slice(&serial.as_bytes()[..n]);
    nv.write_factory(&mut f).unwrap();

    let nv = Arc::new(Mutex::new(nv));
    let mp: Arc<dyn ManifestProvider> = Arc::new(SuitProvider::new(vec![0u8; 32]));
    let backend: Arc<ComponentBackend<MemBlockDevice>> = Arc::new(ComponentBackend::new(
        BankSet::Vm2,
        nv,
        mp,
        ComponentConfig::default(),
    ));

    // Router with the engine on its VM side + a bare container component.
    let container: Arc<dyn Component> = Arc::new(BareComponent {
        id: "container_image",
        caps: Capabilities::default(),
    });
    let vm: Arc<dyn Component> = Arc::new(component_mgr::component_adapter::ComponentAdapter::new(
        backend.clone(),
    ));
    let router: Arc<dyn Component> = Arc::new(AppInstallRouterComponent::new(
        "vm2",
        vm,
        container,
        Arc::new(AcceptingManifestProvider),
    ));
    let engine: Arc<dyn DiagnosticBackend> = backend.clone();
    (InstallRouterDiag::new(router, engine), backend)
}

struct BareComponent {
    id: &'static str,
    caps: Capabilities,
}

#[async_trait]
impl Component for BareComponent {
    fn id(&self) -> &str {
        self.id
    }
    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }
}

/// `read_data("serial_number")` delegates to the engine and returns the real
/// NV-seeded value — NOT `ParameterNotFound`. (The old round-trip adapter's
/// broken data re-implementation is what made identity reads 404; the engine
/// owns the single data authority now.)
#[tokio::test]
async fn read_data_delegates_to_engine_real_value() {
    let (diag, _engine) = router_diag_with_factory("VM2-SERIAL-9");

    let vals = diag
        .read_data(&["serial_number".to_string()])
        .await
        .unwrap();
    assert_eq!(vals.len(), 1);
    assert_eq!(vals[0].id, "serial_number");
    assert_eq!(
        vals[0].value,
        serde_json::Value::String("VM2-SERIAL-9".into())
    );
    assert_eq!(vals[0].did.as_deref(), Some("F18C"));
}

/// `read_data("fw_version")` delegates *identically* to the engine: the
/// wrapper returns exactly what the engine returns (real value when a signed
/// manifest is committed, `ParameterNotFound` otherwise). Proves the wrapper
/// adds no divergent data behavior — it's pure delegation.
#[tokio::test]
async fn read_data_fw_version_matches_engine() {
    let (diag, engine) = router_diag_with_factory("VM2-SERIAL-9");

    let via_wrapper = diag.read_data(&["fw_version".to_string()]).await;
    let via_engine = engine.read_data(&["fw_version".to_string()]).await;

    // Same Ok/Err shape and, when Ok, same value — byte-for-byte delegation.
    match (via_wrapper, via_engine) {
        (Ok(w), Ok(e)) => assert_eq!(
            w.into_iter().map(|v| v.value).collect::<Vec<_>>(),
            e.into_iter().map(|v| v.value).collect::<Vec<_>>(),
        ),
        (Err(w), Err(e)) => assert_eq!(format!("{w:?}"), format!("{e:?}")),
        (w, e) => panic!("wrapper/engine diverged: {w:?} vs {e:?}"),
    }
}

/// A fault read delegates to the engine and returns a real (empty) result, not
/// an error — proving faults go through the engine's NV-backed store.
#[tokio::test]
async fn get_faults_delegates_to_engine() {
    let (diag, _engine) = router_diag_with_factory("VM2-SERIAL-9");

    let res = diag.get_faults(None).await.unwrap();
    assert!(res.faults.is_empty());
}

/// Spy router `Component` that records whether `abort_install` was invoked, so
/// a test can prove `InstallRouterDiag::abort_flash` routes through the router
/// (the vm2/app path) rather than the engine.
struct AbortSpy {
    id: &'static str,
    caps: Capabilities,
    aborted: Arc<AtomicUsize>,
}

#[async_trait]
impl Component for AbortSpy {
    fn id(&self) -> &str {
        self.id
    }
    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }
    async fn abort_install(&self, _id: &FlashId) -> MachineResult<()> {
        self.aborted.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// `abort_flash` on the vm2 wrapper routes to the router `Component`'s
/// `abort_install` (the install router owns the in-VM-vs-VM lifecycle), NOT the
/// engine — the dual of the directly-wired `ComponentBackend::abort_flash`
/// path. Together they cover abort for both wirings.
#[tokio::test]
async fn abort_flash_routes_through_router() {
    let aborted = Arc::new(AtomicUsize::new(0));
    let router: Arc<dyn Component> = Arc::new(AbortSpy {
        id: "vm2",
        caps: Capabilities::default(),
        aborted: aborted.clone(),
    });
    let diag = InstallRouterDiag::new(router, engine_backend());

    diag.abort_flash("t1").await.unwrap();
    assert_eq!(
        aborted.load(Ordering::SeqCst),
        1,
        "abort_flash must route through the router's abort_install"
    );
}
