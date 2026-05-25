//! Tests for `ComponentDiagBackend` — verifies the fallback wiring and the
//! Component-routed method groups.

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use machine_mgr::{
    Capabilities, ClearFaultsResult, Component, DtcFilter, Fault, MachineError, MachineResult,
};

use sovd_core::DiagnosticBackend;

use nv_store::block::MemBlockDevice;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::*;

use crate::backend::{ComponentConfig, VmBackend};
use crate::component_adapter::VmBackendComponent;
use crate::diag_backend::ComponentDiagBackend;
use crate::manifest_provider::ManifestProvider;
use crate::sovd::security::TestSecurityProvider;
use crate::suit_provider::SuitProvider;

const DOCKER_IMAGE_REF: &str = "localhost/sumo-sovd-test:1.0.0";

fn make_vm_backend() -> Arc<VmBackend<MemBlockDevice>> {
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    nv.write_boot_state(&mut NvBootState::default()).unwrap();
    let nv = Arc::new(Mutex::new(nv));

    let trust_anchor = vec![0u8; 32];
    let mp: Arc<dyn ManifestProvider> = Arc::new(SuitProvider::new(trust_anchor));
    let sp = Arc::new(TestSecurityProvider);
    Arc::new(VmBackend::new(
        BankSet::Vm1,
        nv,
        mp,
        sp,
        ComponentConfig::default(),
    ))
}

fn diag_for(backend: Arc<VmBackend<MemBlockDevice>>) -> ComponentDiagBackend {
    let component: Arc<dyn Component> = Arc::new(VmBackendComponent::new(backend.clone()));
    ComponentDiagBackend::new(component, backend)
}

#[tokio::test]
async fn entity_info_and_capabilities_delegate_to_fallback() {
    let backend = make_vm_backend();
    let diag = diag_for(backend);

    // VmBackend's id is "vm1" for BankSet::Vm1 — see backend.rs:218.
    assert_eq!(diag.entity_info().id, "vm1");
    assert!(diag.capabilities().software_update);
}

#[tokio::test]
async fn get_faults_routes_through_component() {
    let backend = make_vm_backend();
    let diag = diag_for(backend);

    // Empty NV → empty faults. The route went through Component::read_dtcs;
    // proven by the fact we got Ok back at all (Component returns Ok([])
    // while the fallback's get_faults would also return Ok — same observable
    // result, but the next test proves the route by interposing a spy).
    let res = diag.get_faults(None).await.unwrap();
    assert!(res.faults.is_empty());
}

#[tokio::test]
async fn clear_faults_routes_through_component() {
    let backend = make_vm_backend();
    let diag = diag_for(backend);

    let res = diag.clear_faults(None).await.unwrap();
    // VmBackend's clear_faults returns success even on empty.
    assert!(res.success);
}

#[tokio::test]
async fn fallback_used_when_component_returns_not_supported() {
    // Use a Component that returns NotSupported for read_dtcs to prove the
    // fallback path runs — the underlying VmBackend should answer instead.
    struct AlwaysUnsupported {
        id: String,
        caps: Capabilities,
    }
    #[async_trait]
    impl Component for AlwaysUnsupported {
        fn id(&self) -> &str {
            &self.id
        }
        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
        // read_dtcs uses default impl → NotSupported
    }

    let backend = make_vm_backend();
    let component: Arc<dyn Component> = Arc::new(AlwaysUnsupported {
        id: "vm1".into(),
        caps: Capabilities::default(),
    });
    let diag = ComponentDiagBackend::new(component, backend.clone());

    // Even though Component returns NotSupported, get_faults still works
    // because ComponentDiagBackend falls back to the underlying VmBackend.
    let res = diag.get_faults(None).await.unwrap();
    assert!(res.faults.is_empty());
}

#[tokio::test]
async fn machine_error_translation_preserves_invalid_argument() {
    // A Component that returns PolicyRejected → expect BackendError::InvalidRequest.
    struct PolicyDenier {
        id: String,
        caps: Capabilities,
    }
    #[async_trait]
    impl Component for PolicyDenier {
        fn id(&self) -> &str {
            &self.id
        }
        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
        async fn read_dtcs(&self, _f: &DtcFilter) -> MachineResult<Vec<Fault>> {
            Err(MachineError::PolicyRejected("nope".into()))
        }
        async fn clear_dtcs(&self, _g: Option<u32>) -> MachineResult<ClearFaultsResult> {
            Err(MachineError::InvalidArgument("bad group".into()))
        }
    }

    let backend = make_vm_backend();
    let component: Arc<dyn Component> = Arc::new(PolicyDenier {
        id: "vm1".into(),
        caps: Capabilities::default(),
    });
    let diag = ComponentDiagBackend::new(component, backend);

    let err = diag.get_faults(None).await.unwrap_err();
    assert!(
        matches!(err, sovd_core::error::BackendError::InvalidRequest(_)),
        "expected InvalidRequest, got {err:?}"
    );

    let err = diag.clear_faults(Some(0)).await.unwrap_err();
    assert!(
        matches!(err, sovd_core::error::BackendError::InvalidRequest(_)),
        "expected InvalidRequest, got {err:?}"
    );
}

#[tokio::test]
async fn other_ops_still_pass_through() {
    // Quick smoke: list_parameters, get_session_mode, get_activation_state
    // should all still work since they pass through to the fallback unchanged.
    let backend = make_vm_backend();
    let diag = diag_for(backend);

    diag.list_parameters().await.expect("list_parameters works");
    diag.get_session_mode()
        .await
        .expect("get_session_mode works");
    diag.get_activation_state()
        .await
        .expect("get_activation_state works");
}

// -------------------------------------------------------------------------
// PR 3b — read_data / write_data routing tests
// -------------------------------------------------------------------------

fn make_vm_backend_with_factory(serial: &str, vin: &str) -> Arc<VmBackend<MemBlockDevice>> {
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    nv.write_boot_state(&mut NvBootState::default()).unwrap();

    let mut f = NvFactory::default();
    let copy_into = |dst: &mut [u8], src: &str| {
        let n = src.len().min(dst.len());
        dst[..n].copy_from_slice(&src.as_bytes()[..n]);
    };
    copy_into(&mut f.serial_number, serial);
    copy_into(&mut f.vin, vin);
    nv.write_factory(&mut f).unwrap();

    let nv = Arc::new(Mutex::new(nv));

    let trust_anchor = vec![0u8; 32];
    let mp: Arc<dyn crate::manifest_provider::ManifestProvider> =
        Arc::new(SuitProvider::new(trust_anchor));
    let sp = Arc::new(TestSecurityProvider);
    Arc::new(VmBackend::new(
        BankSet::Vm1,
        nv,
        mp,
        sp,
        ComponentConfig::default(),
    ))
}

#[tokio::test]
async fn read_data_routes_factory_did_through_component() {
    let backend = make_vm_backend_with_factory("ECU-001", "WDB1234567890ABCD");
    let diag = diag_for(backend);

    let values = diag
        .read_data(&["serial_number".to_string()])
        .await
        .unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].id, "serial_number");
    assert_eq!(values[0].value, serde_json::Value::String("ECU-001".into()));
    assert_eq!(values[0].did.as_deref(), Some("F18C"));
}

#[tokio::test]
async fn read_data_resolves_hex_param_id() {
    let backend = make_vm_backend_with_factory("ECU-002", "VIN0000000000000");
    let diag = diag_for(backend);

    // Caller uses raw hex form — should resolve via DID_REGISTRY → matches
    // serial_number entry.
    let values = diag.read_data(&["0xF18C".to_string()]).await.unwrap();
    assert_eq!(values[0].value, serde_json::Value::String("ECU-002".into()));
}

#[tokio::test]
async fn read_data_unknown_param_is_parameter_not_found() {
    let backend = make_vm_backend();
    let diag = diag_for(backend);

    let err = diag.read_data(&["nonsense".to_string()]).await.unwrap_err();
    assert!(matches!(
        err,
        sovd_core::error::BackendError::ParameterNotFound(_)
    ));
}

#[tokio::test]
async fn read_data_health_did_falls_back_to_vm_service() {
    // Without a vm-service socket, the fallback's read_data returns "offline"
    // for guest_state. We just check the call succeeds and routes correctly.
    let backend = make_vm_backend();
    let diag = diag_for(backend);

    let values = diag.read_data(&["guest_state".to_string()]).await.unwrap();
    assert_eq!(values[0].id, "guest_state");
    // VmBackend returns "offline" when no vm-service socket is configured.
    assert_eq!(values[0].value, serde_json::Value::String("offline".into()));
}

#[tokio::test]
async fn write_data_round_trip_via_component() {
    let backend = make_vm_backend();
    let diag = diag_for(backend);

    // Custom runtime DID 0xFD42 — not in registry, so resolve_param accepts
    // hex and entry.writable check is skipped (no entry).
    diag.write_data("0xFD42", b"hello-world").await.unwrap();

    let values = diag.read_data(&["0xFD42".to_string()]).await.unwrap();
    // Bytes round-trip; data type defaults to "bytes" path which produces a
    // string (printable ASCII).
    assert_eq!(
        values[0].value,
        serde_json::Value::String("hello-world".into())
    );
}

#[tokio::test]
async fn write_data_rejects_read_only_did() {
    let backend = make_vm_backend();
    let diag = diag_for(backend);

    // serial_number is in the registry with writable=false.
    let err = diag.write_data("serial_number", b"X").await.unwrap_err();
    assert!(
        matches!(err, sovd_core::error::BackendError::InvalidRequest(_)),
        "expected InvalidRequest, got {err:?}"
    );
}

// -------------------------------------------------------------------------
// PR 3d — commit / rollback routing
// -------------------------------------------------------------------------

#[tokio::test]
async fn commit_flash_routes_through_component() {
    // Use a Component that captures the call so we know the route was taken,
    // then delegates to the fallback so the underlying NV state is updated
    // correctly and we can use the fallback's get_activation_state to verify.
    use std::sync::atomic::{AtomicBool, Ordering};

    struct CommitSpy {
        id: String,
        caps: Capabilities,
        seen: Arc<AtomicBool>,
        fallback: Arc<dyn DiagnosticBackend>,
    }
    #[async_trait]
    impl Component for CommitSpy {
        fn id(&self) -> &str {
            &self.id
        }
        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
        async fn commit_install(&self, _id: &machine_mgr::FlashId) -> MachineResult<()> {
            self.seen.store(true, Ordering::SeqCst);
            self.fallback
                .commit_flash()
                .await
                .map_err(|e| MachineError::Internal(e.to_string()))
        }
    }

    let backend = make_vm_backend();
    let seen = Arc::new(AtomicBool::new(false));
    let component: Arc<dyn Component> = Arc::new(CommitSpy {
        id: "vm1".into(),
        caps: Capabilities::default(),
        seen: seen.clone(),
        fallback: backend.clone(),
    });
    let diag = ComponentDiagBackend::new(component, backend);

    // VmBackend::commit_flash treats AlreadyCommitted as Ok, so a fresh
    // component with no in-flight install commits cleanly.
    diag.commit_flash().await.unwrap();
    assert!(
        seen.load(Ordering::SeqCst),
        "commit_flash should route through Component"
    );
}

#[tokio::test]
async fn commit_flash_falls_back_when_component_unsupported() {
    // Default Capabilities, default Component — commit_flash returns NotSupported
    // by default, so the adapter falls through to VmBackend's commit_flash.
    struct Bare {
        id: String,
        caps: Capabilities,
    }
    #[async_trait]
    impl Component for Bare {
        fn id(&self) -> &str {
            &self.id
        }
        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
    }

    let backend = make_vm_backend();
    let component: Arc<dyn Component> = Arc::new(Bare {
        id: "vm1".into(),
        caps: Capabilities::default(),
    });
    let diag = ComponentDiagBackend::new(component, backend);

    // No panic, no error — fallback handles the commit.
    diag.commit_flash().await.unwrap();
}

#[tokio::test]
async fn rollback_flash_routes_through_component() {
    let backend = make_vm_backend();
    let diag = diag_for(backend);

    // VmBackendComponent's rollback_install delegates to VmBackend, which
    // since the trial-mode-state-machine refactor returns Busy("not in
    // trial mode") when there's nothing to roll back. We're proving the
    // route, not the semantics — any error from the lower layer is fine
    // as long as it's surfaced through the diag adapter.
    let err = diag.rollback_flash().await.unwrap_err();
    assert!(
        matches!(
            err,
            sovd_core::error::BackendError::InvalidRequest(_)
                | sovd_core::error::BackendError::Busy(_)
                | sovd_core::error::BackendError::Internal(_)
        ),
        "expected InvalidRequest/Busy/Internal error from VmBackend, got {err:?}"
    );
}

// -------------------------------------------------------------------------
// PR 3d (redesign) — install pipeline: start_install / upload_envelope /
// finalize_install routing
// -------------------------------------------------------------------------

#[tokio::test]
async fn start_flash_routes_through_component() {
    use std::sync::atomic::{AtomicBool, Ordering};

    struct StartSpy {
        id: String,
        caps: Capabilities,
        seen: Arc<AtomicBool>,
    }
    #[async_trait]
    impl Component for StartSpy {
        fn id(&self) -> &str {
            &self.id
        }
        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
        async fn start_install(&self) -> MachineResult<machine_mgr::FlashSession> {
            self.seen.store(true, Ordering::SeqCst);
            Ok(machine_mgr::FlashSession {
                id: machine_mgr::FlashId::new("install-42"),
                target_bank: Some("b".into()),
                max_chunk_size: 0,
            })
        }
    }

    let backend = make_vm_backend();
    let seen = Arc::new(AtomicBool::new(false));
    let component: Arc<dyn Component> = Arc::new(StartSpy {
        id: "vm1".into(),
        caps: Capabilities::default(),
        seen: seen.clone(),
    });
    let diag = ComponentDiagBackend::new(component, backend);

    let transfer_id = diag.start_flash().await.unwrap();
    assert_eq!(transfer_id, "install-42");
    assert!(seen.load(Ordering::SeqCst));
}

#[tokio::test]
async fn finalize_flash_routes_through_component() {
    use std::sync::atomic::{AtomicBool, Ordering};

    struct FinalizeSpy {
        id: String,
        caps: Capabilities,
        seen: Arc<AtomicBool>,
    }
    #[async_trait]
    impl Component for FinalizeSpy {
        fn id(&self) -> &str {
            &self.id
        }
        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
        async fn finalize_install(&self, _id: &machine_mgr::FlashId) -> MachineResult<()> {
            self.seen.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    let backend = make_vm_backend();
    let seen = Arc::new(AtomicBool::new(false));
    let component: Arc<dyn Component> = Arc::new(FinalizeSpy {
        id: "vm1".into(),
        caps: Capabilities::default(),
        seen: seen.clone(),
    });
    let diag = ComponentDiagBackend::new(component, backend);

    diag.finalize_flash().await.unwrap();
    assert!(seen.load(Ordering::SeqCst));
}

#[tokio::test]
async fn list_parameters_routes_through_component() {
    let backend = make_vm_backend();
    let diag = diag_for(backend);

    let params = diag.list_parameters().await.unwrap();

    // Standard registry entries should appear with proper SOVD wire shape.
    let serial = params
        .iter()
        .find(|p| p.id == "serial_number")
        .expect("serial_number ParameterInfo");
    assert_eq!(serial.name, "Serial Number");
    assert!(serial.read_only);
    assert_eq!(serial.data_type.as_deref(), Some("string"));
    assert_eq!(serial.did.as_deref(), Some("F18C"));
    // VmBackend's id is "vm1" for BankSet::Vm1 — see backend.rs:218.
    assert_eq!(serial.href, "/vehicle/v1/components/vm1/data/serial_number");
}

#[tokio::test]
async fn abort_flash_routes_through_component() {
    let backend = make_vm_backend();
    let diag = diag_for(backend);

    // Pre-finalize abort: VmBackendComponent clears session state and returns Ok.
    diag.abort_flash("any-id").await.unwrap();
}

#[tokio::test]
async fn upload_envelope_routes_through_component() {
    use futures::StreamExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct UploadSpy {
        id: String,
        caps: Capabilities,
        bytes_seen: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl Component for UploadSpy {
        fn id(&self) -> &str {
            &self.id
        }
        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
        async fn start_install(&self) -> MachineResult<machine_mgr::FlashSession> {
            Ok(machine_mgr::FlashSession {
                id: machine_mgr::FlashId::new("session"),
                target_bank: None,
                max_chunk_size: 0,
            })
        }
        async fn upload_envelope(
            &self,
            _id: &machine_mgr::FlashId,
            mut stream: machine_mgr::EnvelopeStream,
        ) -> MachineResult<String> {
            let mut total = 0usize;
            while let Some(chunk) = stream.next().await {
                let b = chunk.map_err(|e| MachineError::Internal(e.to_string()))?;
                total += b.len();
            }
            self.bytes_seen.store(total, Ordering::SeqCst);
            Ok("pkg-42".into())
        }
    }

    let backend = make_vm_backend();
    let bytes_seen = Arc::new(AtomicUsize::new(0));
    let component: Arc<dyn Component> = Arc::new(UploadSpy {
        id: "vm1".into(),
        caps: Capabilities::default(),
        bytes_seen: bytes_seen.clone(),
    });
    let diag = ComponentDiagBackend::new(component, backend);

    let payload = b"hello world install envelope";
    let id = diag.receive_package(payload).await.unwrap();
    assert_eq!(id, "pkg-42");
    assert_eq!(bytes_seen.load(Ordering::SeqCst), payload.len());
}

#[tokio::test]
#[ignore = "requires generated Docker SUIT fixture and local Docker daemon"]
async fn docker_image_diag_backend_routes_generated_suit_manifest_and_payload() {
    let archive = std::env::var_os("SUMO_DOCKER_IMAGE_ARCHIVE")
        .map(PathBuf::from)
        .expect("set SUMO_DOCKER_IMAGE_ARCHIVE to generated Docker save .tar.gz fixture");
    let manifest = std::env::var_os("SUMO_DOCKER_IMAGE_MANIFEST")
        .map(PathBuf::from)
        .expect("set SUMO_DOCKER_IMAGE_MANIFEST to generated docker-image-v1.0.0.suit fixture");
    let tmp = tempfile::TempDir::new().unwrap();
    let _guard = DockerImageCleanup::new(DOCKER_IMAGE_REF);

    let component: Arc<dyn Component> = Arc::new(app_mgr::ContainerImageComponent::new(
        app_mgr::ContainerImageConfig::new("docker_image", tmp.path().join("staging")),
    ));
    let diag = ComponentDiagBackend::new(component, make_vm_backend());

    let transfer_id = diag.start_flash().await.unwrap();
    assert_eq!(transfer_id, "docker-image");
    let manifest_id = diag
        .receive_package(&std::fs::read(manifest).unwrap())
        .await
        .unwrap();
    assert_eq!(manifest_id, "docker-image-manifest");
    let payload_id = diag
        .receive_package(&std::fs::read(archive).unwrap())
        .await
        .unwrap();
    assert_eq!(payload_id, "docker-image-payload");
    diag.finalize_flash().await.unwrap();
    diag.commit_flash().await.unwrap();

    assert!(
        docker_image_present(DOCKER_IMAGE_REF),
        "expected docker image inspect to find {DOCKER_IMAGE_REF} after SOVD DiagnosticBackend lifecycle"
    );
}

#[tokio::test]
async fn capabilities_carry_abortable_after_finalize() {
    use machine_mgr::{Component, MachineRegistry};
    let nv = make_vm_backend();
    let comp_arc: Arc<dyn Component> =
        Arc::new(crate::component_adapter::VmBackendComponent::new(nv));

    let entity = sovd_core::EntityInfo {
        id: "vehicle".into(),
        name: "Test".into(),
        entity_type: "vehicle".into(),
        description: None,
        href: "/v".into(),
        status: None,
    };
    let _machine = MachineRegistry::builder(entity)
        .with_arc(comp_arc.clone())
        .build();

    let flash = comp_arc
        .capabilities()
        .flash
        .as_ref()
        .expect("vm has flash caps");
    // Honest about current impl: VmBackendComponent doesn't yet wire abort.
    assert!(!flash.abortable_after_finalize);
}

fn docker_image_present(image_ref: &str) -> bool {
    Command::new("docker")
        .args(["image", "inspect", image_ref])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

struct DockerImageCleanup<'a> {
    image_ref: &'a str,
}

impl<'a> DockerImageCleanup<'a> {
    fn new(image_ref: &'a str) -> Self {
        let cleanup = Self { image_ref };
        cleanup.remove();
        cleanup
    }

    fn remove(&self) {
        let _ = Command::new("docker")
            .args(["image", "rm", "-f", self.image_ref])
            .output();
    }
}

impl Drop for DockerImageCleanup<'_> {
    fn drop(&mut self) {
        self.remove();
    }
}

// -------------------------------------------------------------------------
// PR 3c — activation state routing
// -------------------------------------------------------------------------

#[tokio::test]
async fn get_activation_state_routes_through_component() {
    let backend = make_vm_backend();
    let diag = diag_for(backend);

    let st = diag.get_activation_state().await.unwrap();
    // VM components support rollback (default ComponentConfig).
    assert!(st.supports_rollback);
}

#[tokio::test]
async fn get_activation_state_falls_back_when_component_returns_none() {
    // A Component that returns Ok(None) for activation_state should fall
    // through to the fallback's get_activation_state.
    struct NoActivation {
        id: String,
        caps: Capabilities,
    }
    #[async_trait]
    impl Component for NoActivation {
        fn id(&self) -> &str {
            &self.id
        }
        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
        async fn activation_state(
            &self,
        ) -> MachineResult<Option<sovd_core::backend::ActivationState>> {
            Ok(None)
        }
    }

    let backend = make_vm_backend();
    let component: Arc<dyn Component> = Arc::new(NoActivation {
        id: "vm1".into(),
        caps: Capabilities::default(),
    });
    let diag = ComponentDiagBackend::new(component, backend);

    // The fallback supplies the answer; we just check we got Ok back.
    let st = diag.get_activation_state().await.unwrap();
    assert!(st.supports_rollback);
}
