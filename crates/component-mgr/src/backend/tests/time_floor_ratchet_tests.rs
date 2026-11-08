use super::super::*;
use crate::manifest_provider::{ManifestError, ManifestProvider, ValidatedFirmware};
use crate::sovd::time_floor::TimeFloor;
use hsm::HsmProvider;
use hsm_sim_backend::SimHsm;
use nv_store::block::MemBlockDevice;
use nv_store::slots;
use nv_store::store::MIN_NV_DEVICE_SIZE;

struct NoopManifest;
impl ManifestProvider for NoopManifest {
    fn validate(&self, _d: &[u8], _m: u32) -> Result<ValidatedFirmware, ManifestError> {
        Err(ManifestError::ParseError("unused".into()))
    }
}

/// A backend carrying a SimHsm (whose monotonic slot is the safe-time floor).
/// Returns the backend + a handle to read the floor back.
fn backend_with_hsm(
    tag: &str,
) -> (
    ComponentBackend<MemBlockDevice>,
    Arc<Mutex<dyn HsmProvider>>,
) {
    let keystore = std::env::temp_dir().join(format!("cm-floor-{tag}"));
    let _ = std::fs::remove_dir_all(&keystore);
    std::fs::create_dir_all(&keystore).unwrap();
    let hsm: Arc<Mutex<dyn HsmProvider>> = Arc::new(Mutex::new(SimHsm::new(keystore)));

    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    nv.write_boot_state(&mut NvBootState::default()).unwrap();
    let backend = ComponentBackend::with_options(
        slots::VM1,
        Arc::new(Mutex::new(nv)),
        Arc::new(NoopManifest),
        ComponentConfig::default(),
        None,
        None,
        Some(hsm.clone()),
    );
    (backend, hsm)
}

fn floor(hsm: &Arc<Mutex<dyn HsmProvider>>) -> u64 {
    TimeFloor::read(&*hsm.lock().unwrap()).unwrap()
}

#[test]
fn ratchet_advances_the_floor_and_is_monotonic() {
    let (backend, hsm) = backend_with_hsm("advance");
    assert_eq!(floor(&hsm), 0, "floor starts unraised");

    backend.ratchet_time_floor(1_784_600_000);
    assert_eq!(floor(&hsm), 1_784_600_000, "floor ratchets up to the iat");

    // A LOWER (stale) iat can never rewind the floor — the safety core.
    backend.ratchet_time_floor(1_000_000_000);
    assert_eq!(
        floor(&hsm),
        1_784_600_000,
        "a stale iat is a no-op, never a rewind"
    );

    // A higher iat advances it further.
    backend.ratchet_time_floor(1_784_600_500);
    assert_eq!(floor(&hsm), 1_784_600_500, "a newer iat advances the floor");
}

#[test]
fn rejected_but_trust_root_signed_manifest_still_ratchets_the_floor() {
    // The load-bearing Piece-1 behaviour: a manifest whose signature verified to
    // a trusted root but which we DISCARD for anti-rollback still carried a
    // truthful signed lower bound on real time — the floor must advance from it.
    let (backend, hsm) = backend_with_hsm("reject");
    assert_eq!(floor(&hsm), 0);

    let too_old = ManifestError::RollbackRejected {
        seq: 3,
        min: 5,
        signing_time_secs: Some(1_784_600_000),
    };
    backend.ratchet_time_floor_on_reject(&too_old);
    assert_eq!(
        floor(&hsm),
        1_784_600_000,
        "a rejected-but-trust-root-signed manifest ratchets the floor from its signed iat"
    );
}

#[test]
fn untrusted_or_timeless_rejections_do_not_move_the_floor() {
    let (backend, hsm) = backend_with_hsm("no-time");

    // Bad signature / parse error → no trusted time → no ratchet.
    backend.ratchet_time_floor_on_reject(&ManifestError::SignatureInvalid("bad".into()));
    backend.ratchet_time_floor_on_reject(&ManifestError::DigestMismatch);
    // RollbackRejected but the manifest carried no signing_time → nothing to adopt.
    backend.ratchet_time_floor_on_reject(&ManifestError::RollbackRejected {
        seq: 3,
        min: 5,
        signing_time_secs: None,
    });
    assert_eq!(
        floor(&hsm),
        0,
        "no trusted signed time present → floor untouched"
    );
}

// --- Piece 2: the x-attest-time SOVD operation ---------------------
use crate::suit_provider::SuitProvider;
use sovd_core::DiagnosticBackend;
use sumo_offboard::{keygen, ImageManifestBuilder};

/// Build a SoftwareAuthority-signed SUIT manifest carrying `signing_time`, plus
/// a SuitProvider that trusts that key as sw-authority, plus the host/device
/// backend — the one the platform nominates to carry attest-time — with a
/// SimHsm. This is the operator-pushed attest-time artifact.
fn host_backend_and_signed_manifest(
    tag: &str,
    signing_time: u64,
) -> (
    ComponentBackend<MemBlockDevice>,
    Arc<Mutex<dyn HsmProvider>>,
    Vec<u8>,
) {
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    // A minimal detached (no payload) manifest — attest-time is verify-only.
    let envelope = ImageManifestBuilder::new()
        .signing_time(signing_time)
        .component_id(vec!["host-os".into(), "ifs".into()])
        .sequence_number(1)
        .payload_digest(&[0u8; 32], 0)
        .payload_uri("#firmware".into())
        .build(&key)
        .unwrap();

    // Provider that trusts our signing key as the software authority.
    let provider = SuitProvider::with_factory_authority();
    provider.update_keys(key.public_key_bytes(), None, None);

    let keystore = std::env::temp_dir().join(format!("cm-attest-{tag}"));
    let _ = std::fs::remove_dir_all(&keystore);
    std::fs::create_dir_all(&keystore).unwrap();
    let hsm: Arc<Mutex<dyn HsmProvider>> = Arc::new(Mutex::new(SimHsm::new(keystore)));

    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    nv.write_boot_state(&mut NvBootState::default()).unwrap();
    let backend = ComponentBackend::with_options(
        slots::OS,
        Arc::new(Mutex::new(nv)),
        Arc::new(provider),
        ComponentConfig::default(),
        None,
        None,
        Some(hsm.clone()),
    )
    .with_id("host-os".into())
    // The platform nominates this component to carry attest-time.
    .with_attest_time(true);
    (backend, hsm, envelope)
}

/// Advertised iff the platform nominated the component AND an HSM is
/// present (the safe-time floor lives in the HSM). Which slot the
/// component sits on never enters the decision.
#[tokio::test]
async fn attest_time_is_advertised_only_when_nominated_and_hsm_backed() {
    let (nominated, _hsm, _) = host_backend_and_signed_manifest("advertise", 1_784_600_000);
    assert!(
        nominated
            .list_operations()
            .await
            .unwrap()
            .iter()
            .any(|o| o.id == ATTEST_TIME_OP_ID),
        "nominated component with an HSM advertises x-attest-time"
    );

    // Same component, same HSM, not nominated → silent.
    let not_nominated = nominated.with_attest_time(false);
    assert!(
        !not_nominated
            .list_operations()
            .await
            .unwrap()
            .iter()
            .any(|o| o.id == ATTEST_TIME_OP_ID),
        "un-nominated component must not advertise x-attest-time"
    );

    // Nominated but HSM-less → still silent; there is no floor to ratchet.
    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    nv.write_boot_state(&mut NvBootState::default()).unwrap();
    let hsmless = ComponentBackend::with_options(
        slots::OS,
        Arc::new(Mutex::new(nv)),
        Arc::new(NoopManifest),
        ComponentConfig::default(),
        None,
        None,
        None,
    )
    .with_attest_time(true);
    assert!(
        hsmless.list_operations().await.unwrap().is_empty(),
        "nomination without an HSM must not advertise x-attest-time"
    );
}

#[tokio::test]
async fn attest_time_verifies_a_signed_manifest_and_ratchets_the_floor() {
    let iat = 1_784_620_143; // the fresh-tower cert not_before from the live repro
    let (backend, hsm, envelope) = host_backend_and_signed_manifest("ratchet", iat);
    assert_eq!(floor(&hsm), 0, "floor starts unraised");

    let exec = backend
        .start_operation(ATTEST_TIME_OP_ID, &envelope)
        .await
        .expect("a sw-authority-signed manifest attests trusted time");
    assert_eq!(exec.status, sovd_core::OperationStatus::Completed);
    assert_eq!(
        floor(&hsm),
        iat,
        "attest-time ratcheted the safe-time floor to the manifest's signed signing_time"
    );
}

#[tokio::test]
async fn attest_time_rejects_a_manifest_not_signed_by_the_trusted_root() {
    // A manifest signed by a DIFFERENT key must not move the floor — the whole
    // security property (independent trusted root, non-circular).
    let (backend, hsm, _good) = host_backend_and_signed_manifest("untrusted", 1_784_620_143);
    let attacker = keygen::generate_signing_key(keygen::ES256).unwrap();
    let forged = ImageManifestBuilder::new()
        .signing_time(9_999_999_999) // far future — the attacker's goal
        .component_id(vec!["host-os".into(), "ifs".into()])
        .sequence_number(1)
        .payload_digest(&[0u8; 32], 0)
        .payload_uri("#firmware".into())
        .build(&attacker)
        .unwrap();

    let res = backend.start_operation(ATTEST_TIME_OP_ID, &forged).await;
    assert!(
        res.is_err(),
        "a manifest not signed by the trusted root is rejected"
    );
    assert_eq!(floor(&hsm), 0, "a forged manifest never moves the floor");
}
