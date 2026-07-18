//! Integration tests: exercise the `machine-mgr::Component` trait against a
//! real `ComponentBackend`. Validates the trait surface, not the diagserver wiring.
#![allow(clippy::field_reassign_with_default)]

use std::sync::{Arc, Mutex};

use bytes::Bytes;

use machine_mgr::{
    Component, DidKind, DtcFilter, EntityInfo, FlashId, MachineError, MachineRegistry,
};

use nv_store::block::MemBlockDevice;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::*;

use crate::backend::{ComponentBackend, ComponentConfig};
use crate::component_adapter::ComponentAdapter;
use crate::did::{DID_SERIAL_NUMBER, DID_VIN};
use crate::manifest_provider::ManifestProvider;
use crate::sovd::security::TestSecurityProvider;
use crate::suit_provider::SuitProvider;

fn make_nv() -> Arc<Mutex<NvStore<MemBlockDevice>>> {
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    let mut state = NvBootState::default();
    nv.write_boot_state(&mut state).unwrap();
    Arc::new(Mutex::new(nv))
}

fn str_arr<const N: usize>(s: &str) -> [u8; N] {
    let mut a = [0u8; N];
    let len = s.len().min(N);
    a[..len].copy_from_slice(&s.as_bytes()[..len]);
    a
}

fn vm_backend(
    nv: Arc<Mutex<NvStore<MemBlockDevice>>>,
    set: BankSet,
    config: ComponentConfig,
) -> Arc<ComponentBackend<MemBlockDevice>> {
    let trust_anchor = vec![0u8; 32];
    let suit_provider = SuitProvider::new(trust_anchor);
    let mp: Arc<dyn ManifestProvider> = Arc::new(suit_provider);
    let sp = Arc::new(TestSecurityProvider);
    Arc::new(ComponentBackend::new(set, nv, mp, sp, config))
}

fn entity() -> EntityInfo {
    EntityInfo {
        id: "vehicle".into(),
        name: "Test Vehicle".into(),
        entity_type: "vehicle".into(),
        description: None,
        href: "/vehicle/v1".into(),
        status: None,
    }
}

#[tokio::test]
async fn component_id_and_capabilities() {
    let nv = make_nv();
    let vm1 = vm_backend(nv, BankSet::Vm1, ComponentConfig::default());
    let comp = ComponentAdapter::new(vm1);

    assert_eq!(comp.id(), "vm1");
    let caps = comp.capabilities();
    assert!(caps.did_store);
    assert!(caps.dtcs);
    assert!(caps.clear_dtcs);

    let flash = caps.flash.as_ref().expect("vm has flash caps");
    assert!(flash.dual_bank);
    assert!(flash.supports_rollback);
    assert!(flash.supports_trial_boot);

    let lc = caps.lifecycle.as_ref().expect("vm has lifecycle caps");
    assert!(lc.restartable);
    assert!(!lc.has_runtime_state); // no vm-service socket configured
    assert!(caps.hsm.is_none()); // no hsm provider configured
}

#[tokio::test]
async fn hsm_component_capabilities_are_single_bank() {
    let nv = make_nv();
    let cfg = ComponentConfig {
        supports_rollback: false,
        single_bank: true,
        entity_type: "hsm".into(),
        log_source: None,
    };
    let hsm = vm_backend(nv, BankSet::Hsm, cfg);
    let comp = ComponentAdapter::new(hsm);

    assert_eq!(comp.id(), "hsm");
    let flash = comp.capabilities().flash.as_ref().unwrap();
    assert!(!flash.dual_bank);
    assert!(!flash.supports_rollback);
    assert!(!flash.supports_trial_boot);
}

#[tokio::test]
async fn read_factory_did_via_component() {
    let nv = make_nv();
    {
        let mut g = nv.lock().unwrap();
        let mut f = NvFactory::default();
        f.serial_number = str_arr("ECU-001");
        f.vin = str_arr("WDB1234567890ABCD");
        g.write_factory(&mut f).unwrap();
    }

    let vm1 = vm_backend(nv, BankSet::Vm1, ComponentConfig::default());
    let comp = ComponentAdapter::new(vm1);

    let serial = comp
        .read_did(DID_SERIAL_NUMBER, DidKind::Factory)
        .await
        .unwrap();
    assert!(serial.starts_with(b"ECU-001"));

    let vin = comp.read_did(DID_VIN, DidKind::Factory).await.unwrap();
    assert!(vin.starts_with(b"WDB1234567890ABCD"));
}

#[tokio::test]
async fn read_did_not_found() {
    let nv = make_nv();
    let vm1 = vm_backend(nv, BankSet::Vm1, ComponentConfig::default());
    let comp = ComponentAdapter::new(vm1);

    let err = comp.read_did(0xABCD, DidKind::Runtime).await.unwrap_err();
    assert!(matches!(err, MachineError::NotFound(_)), "got {err:?}");
}

#[tokio::test]
async fn write_runtime_did_then_read_back() {
    let nv = make_nv();
    let vm1 = vm_backend(nv, BankSet::Vm1, ComponentConfig::default());
    let comp = ComponentAdapter::new(vm1);

    comp.write_did(0xFD10, DidKind::Runtime, b"hello")
        .await
        .unwrap();
    let v = comp.read_did(0xFD10, DidKind::Runtime).await.unwrap();
    assert_eq!(v, Bytes::from_static(b"hello"));
}

#[tokio::test]
async fn write_factory_did_rejected() {
    let nv = make_nv();
    let vm1 = vm_backend(nv, BankSet::Vm1, ComponentConfig::default());
    let comp = ComponentAdapter::new(vm1);

    let err = comp
        .write_did(DID_SERIAL_NUMBER, DidKind::Factory, b"X")
        .await
        .unwrap_err();
    assert!(
        matches!(err, MachineError::PolicyRejected(_)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn activation_state_returns_some() {
    let nv = make_nv();
    let vm1 = vm_backend(nv, BankSet::Vm1, ComponentConfig::default());
    let comp = ComponentAdapter::new(vm1);

    let st = comp.activation_state().await.unwrap().expect("Some(state)");
    assert!(st.supports_rollback);
}

#[tokio::test]
async fn read_dtcs_empty() {
    let nv = make_nv();
    let vm1 = vm_backend(nv, BankSet::Vm1, ComponentConfig::default());
    let comp = ComponentAdapter::new(vm1);

    let dtcs = comp.read_dtcs(&DtcFilter::default()).await.unwrap();
    assert!(dtcs.is_empty());
}

#[tokio::test]
async fn rollback_unsupported_for_hsm() {
    let nv = make_nv();
    let cfg = ComponentConfig {
        supports_rollback: false,
        single_bank: true,
        entity_type: "hsm".into(),
        log_source: None,
    };
    let hsm = vm_backend(nv, BankSet::Hsm, cfg);
    let comp = ComponentAdapter::new(hsm);

    let err = comp
        .rollback_install(&FlashId::new("dummy"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, MachineError::InvalidArgument(_)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn defaults_return_not_supported() {
    let nv = make_nv();
    let vm1 = vm_backend(nv, BankSet::Vm1, ComponentConfig::default());
    let comp = ComponentAdapter::new(vm1);

    // Methods not yet wired must still return NotSupported.
    // (CSR requires explicit with_csr_keystore; install_keys has no use case yet.)
    let err = comp.get_csr("device-decrypt").await.unwrap_err();
    assert!(matches!(err, MachineError::NotSupported(_)));

    let err = comp.install_keys(&[]).await.unwrap_err();
    assert!(matches!(err, MachineError::NotSupported(_)));
}

#[tokio::test]
async fn get_csr_not_supported_without_keystore() {
    let nv = make_nv();
    let vm1 = vm_backend(nv, BankSet::Vm1, ComponentConfig::default());
    let comp = ComponentAdapter::new(vm1);

    // No with_csr_keystore call → NotSupported.
    let err = comp.get_csr("device-decrypt").await.unwrap_err();
    assert!(matches!(err, MachineError::NotSupported(_)), "got {err:?}");
    assert!(comp.capabilities().hsm.is_none());
}

#[tokio::test]
async fn get_csr_generates_csr_when_keystore_configured() {
    use std::path::PathBuf;
    let nv = make_nv();
    let vm = vm_backend(
        nv,
        BankSet::Hsm,
        ComponentConfig {
            supports_rollback: false,
            single_bank: true,
            entity_type: "hsm".into(),
            log_source: None,
        },
    );

    // Use a tempdir for the keystore — SimHsm will lazily create the device
    // key on first use.
    let tmp = tempfile::tempdir().expect("tempdir");
    let keystore = PathBuf::from(tmp.path());

    // Pre-generate the device key as the real flow does, so CSR signing has
    // something to sign with.
    let setup = hsm_sim_backend::SimHsm::new(keystore.clone());
    setup.ensure_device_keys().expect("device keys created");

    let comp = ComponentAdapter::new(vm).with_csr_keystore(keystore);

    // Capability should reflect CSR support.
    assert!(comp.capabilities().hsm.as_ref().unwrap().supports_csr);

    // tls-identity is the canonical cert-bearing key; ensure_device_keys
    // generates every device-generated role, so the slot exists to sign over.
    let csr = comp.get_csr("tls-identity").await.expect("csr generated");
    // PKCS#10 CSR DER blobs start with a SEQUENCE tag (0x30).
    assert!(!csr.as_bytes().is_empty());
    assert_eq!(csr.as_bytes()[0], 0x30);
}

#[tokio::test]
async fn get_device_id_returns_a_stable_device_key_thumbprint() {
    use std::path::PathBuf;
    let nv = make_nv();
    let vm = vm_backend(
        nv,
        BankSet::Hsm,
        ComponentConfig {
            supports_rollback: false,
            single_bank: true,
            entity_type: "hsm".into(),
            log_source: None,
        },
    );
    let tmp = tempfile::tempdir().expect("tempdir");
    let keystore = PathBuf::from(tmp.path());
    let setup = hsm_sim_backend::SimHsm::new(keystore.clone());
    setup.ensure_device_keys().expect("device keys created");
    let comp = ComponentAdapter::new(vm).with_csr_keystore(keystore);

    let id = comp
        .get_device_id()
        .await
        .expect("ok")
        .expect("device id present");
    assert_eq!(id.len(), 64, "hex SHA-256 thumbprint");
    let again = comp.get_device_id().await.expect("ok").expect("present");
    assert_eq!(id, again, "stable across calls");
}

#[tokio::test]
async fn abort_install_clears_session_pre_finalize() {
    use machine_mgr::FlashId;

    let nv = make_nv();
    let vm1 = vm_backend(nv, BankSet::Vm1, ComponentConfig::default());
    let comp = ComponentAdapter::new(vm1);

    // No session in flight — abort is a no-op success.
    comp.abort_install(&FlashId::new("nope")).await.unwrap();
    assert!(!comp.inner().flash_is_finalized());
}

#[tokio::test]
async fn defaults_return_not_supported_after_abort_wired() {
    // Sanity: abort_install is now wired; another defaulted method should
    // still surface NotSupported. install_keys is the remaining one.
    let nv = make_nv();
    let vm1 = vm_backend(nv, BankSet::Vm1, ComponentConfig::default());
    let comp = ComponentAdapter::new(vm1);

    let err = comp.install_keys(&[]).await.unwrap_err();
    assert!(matches!(err, MachineError::NotSupported(_)), "got {err:?}");
}

#[tokio::test]
async fn list_dids_returns_registry_minus_health_when_no_vm_service() {
    use machine_mgr::DidFilter;

    let nv = make_nv();
    let vm1 = vm_backend(nv, BankSet::Vm1, ComponentConfig::default());
    let comp = ComponentAdapter::new(vm1);

    let dids = comp.list_dids(&DidFilter::default()).await.unwrap();

    // serial_number, vin, fw_version, etc. should be present.
    assert!(dids.iter().any(|d| d.id == "serial_number"));
    assert!(dids.iter().any(|d| d.id == "vin"));

    // Health DIDs should NOT be present without a vm-service socket.
    assert!(!dids.iter().any(|d| d.id == "guest_state"));
    assert!(!dids.iter().any(|d| d.id == "heartbeat_seq"));

    // Read-only flags propagate.
    let serial = dids.iter().find(|d| d.id == "serial_number").unwrap();
    assert!(!serial.writable);
}

#[tokio::test]
async fn list_dids_includes_runtime_dids_from_nv() {
    use machine_mgr::{DidFilter, DidKind};

    let nv = make_nv();
    let vm1 = vm_backend(nv, BankSet::Vm1, ComponentConfig::default());
    let comp = ComponentAdapter::new(vm1);

    // Write a custom runtime DID — should appear in list_dids.
    comp.write_did(0xFD42, DidKind::Runtime, b"abc")
        .await
        .unwrap();

    let dids = comp.list_dids(&DidFilter::default()).await.unwrap();
    let runtime = dids
        .iter()
        .find(|d| d.key == 0xFD42)
        .expect("runtime DID listed");
    assert_eq!(runtime.id, "runtime_FD42");
    assert!(runtime.writable);
}

#[tokio::test]
async fn machine_registry_holds_multiple_components() {
    let nv = make_nv();
    let vm1 = ComponentAdapter::new(vm_backend(
        nv.clone(),
        BankSet::Vm1,
        ComponentConfig::default(),
    ));
    let vm2 = ComponentAdapter::new(vm_backend(
        nv.clone(),
        BankSet::Vm2,
        ComponentConfig::default(),
    ));
    let hsm = ComponentAdapter::new(vm_backend(
        nv,
        BankSet::Hsm,
        ComponentConfig {
            supports_rollback: false,
            single_bank: true,
            entity_type: "hsm".into(),
            log_source: None,
        },
    ));

    let machine = MachineRegistry::builder(entity())
        .with(vm1)
        .with(vm2)
        .with(hsm)
        .try_build()
        .expect("no duplicate ids");

    use machine_mgr::Machine;
    assert_eq!(machine.components().len(), 3);
    assert_eq!(machine.component("vm1").unwrap().id(), "vm1");
    assert_eq!(machine.component("vm2").unwrap().id(), "vm2");
    assert_eq!(machine.component("hsm").unwrap().id(), "hsm");
    assert!(machine.component("nope").is_none());

    // Capabilities differ: HSM is single-bank, vms are dual-bank.
    let hsm_caps = machine.component("hsm").unwrap().capabilities();
    assert!(!hsm_caps.flash.as_ref().unwrap().dual_bank);
    let vm1_caps = machine.component("vm1").unwrap().capabilities();
    assert!(vm1_caps.flash.as_ref().unwrap().dual_bank);
}
