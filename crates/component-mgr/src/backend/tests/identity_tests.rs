// ---------------------------------------------------------------------------
// Single-source SW identity: end-to-end tests proving the F187-F19E
// identification DIDs are served from the signed IVD manifest (not NV),
// the cache invalidates, and a tampered manifest is refused.
// ---------------------------------------------------------------------------
use super::super::*;
use crate::manifest_provider::ManifestError;
use crate::ota::ImageMeta;
use hsm::HsmProvider;
use hsm_sim_backend::SimHsm;
use nv_store::block::MemBlockDevice;
use nv_store::slots;
use nv_store::store::MIN_NV_DEVICE_SIZE;
use std::path::Path;

/// Manifest provider stub — the identity path never validates a SUIT
/// envelope (the package is injected directly), so this can be inert.
struct NoopManifest;
impl ManifestProvider for NoopManifest {
    fn validate(&self, _d: &[u8], _m: u32) -> Result<ValidatedFirmware, ManifestError> {
        Err(ManifestError::ParseError("unused in identity tests".into()))
    }
}

/// Build a fully-provisioned SimHsm: keystore manifest present (so
/// `is_provisioned()` is true) plus the device `ivd-signing` keypair
/// (so `sign`/`verify` work). Mirrors `hsm::ivd` test setup.
fn provisioned_hsm(
    tag: &str,
) -> (
    Arc<Mutex<dyn hsm::HsmProvider>>,
    Arc<dyn hsm::HsmCryptoProvider>,
    PathBuf,
) {
    use hsm::payload::*;
    let keystore = std::env::temp_dir().join(format!("component-mgr-identity-ks-{tag}"));
    let _ = std::fs::remove_dir_all(&keystore);
    std::fs::create_dir_all(&keystore).unwrap();

    let hsm = SimHsm::new(keystore.clone());
    let ks = HsmKeystore {
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
    };
    hsm.write_keystore(&ks).unwrap();
    hsm.ensure_device_keys().unwrap();
    std::fs::write(keystore.join("provision_state"), b"1\n").unwrap();
    assert!(hsm.is_provisioned().unwrap());

    // A second SimHsm over the same keystore is the crypto handle (IVD
    // sign/verify); the first SimHsm is the provisioning-authority provider.
    let crypto: Arc<dyn hsm::HsmCryptoProvider> = Arc::new(SimHsm::new(keystore.clone()));
    (Arc::new(Mutex::new(hsm)), crypto, keystore)
}

fn sample_image_meta() -> ImageMeta {
    let mut m = ImageMeta::default();
    let set = |dst: &mut [u8], s: &[u8]| dst[..s.len()].copy_from_slice(s);
    set(&mut m.fw_version, b"1.2.0");
    set(&mut m.spare_part_number, b"VM1-SPARE-001");
    set(&mut m.ecu_sw_number, b"VM1-SW-001");
    set(&mut m.supplier_sw_number, b"SUP-SW-VM1-001");
    set(&mut m.supplier_sw_version, b"1.2.0");
    set(&mut m.odx_file_id, b"ODX-VM1-V1");
    set(&mut m.system_name, b"VM1-Linux");
    set(&mut m.programming_date, b"20260604");
    set(&mut m.tester_serial, b"SOVD-OTA");
    m
}

/// Construct a ComponentBackend (vm1) with images_dir + provisioned HSM,
/// inject a Verified package carrying `meta`, and point the flash
/// transfer at it so `ivd_sign_staged_bank` picks up its identity.
fn backend_with_package(
    tag: &str,
    meta: ImageMeta,
) -> (ComponentBackend<MemBlockDevice>, PathBuf, PathBuf) {
    let images_dir = std::env::temp_dir().join(format!("component-mgr-identity-img-{tag}"));
    let _ = std::fs::remove_dir_all(&images_dir);
    std::fs::create_dir_all(&images_dir).unwrap();

    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    nv.write_boot_state(&mut boot).unwrap();
    let nv = Arc::new(Mutex::new(nv));

    let (hsm, crypto, keystore) = provisioned_hsm(tag);

    let backend = ComponentBackend::with_options(
        slots::VM1,
        nv,
        Arc::new(NoopManifest),
        ComponentConfig::default(),
        None,
        Some(images_dir.clone()),
        Some(hsm),
    )
    .with_bank_spec(crate::bank_spec::BankSetSpec {
        dir_name: "vm1".into(),
    })
    .with_hsm_crypto(crypto);

    // Stage a payload file in the target (bank_b) so the bank isn't
    // payload-empty and signing actually runs.
    let bank_dir = images_dir.join("vm1").join("bank_b");
    std::fs::create_dir_all(&bank_dir).unwrap();
    std::fs::write(bank_dir.join("rootfs.img"), b"vm1 rootfs bytes").unwrap();

    // Inject a Verified package + a flash transfer pointing at it.
    let pkg_id = "pkg-1".to_string();
    backend.packages.lock().unwrap().insert(
        pkg_id.clone(),
        StoredPackage {
            id: pkg_id.clone(),
            validated: ValidatedFirmware {
                component_name: "vm1".into(),
                manifest_type: ManifestType::Firmware,
                image_meta: meta,
                image_data: Vec::new(),
                version_display: "1.2.0".into(),
                image_sha256: Some([0xAB; 32]),
                image_size: Some(16),
                raw_envelope: None,
                streamed_files: Vec::new(),
                signing_time_secs: None,
                disable_target: None,
            },
            status: PackageStatus::Verified,
        },
    );
    *backend.flash_transfer.lock().unwrap() = Some(FlashTransferState {
        transfer_id: "t1".into(),
        package_id: pkg_id,
        state: FlashState::AwaitingActivation,
        pre_reset_health: None,
        image_size: 16,
        streamed_files: Vec::new(),
    });

    (backend, images_dir, keystore)
}

fn cleanup(images_dir: &Path, keystore: &Path) {
    let _ = std::fs::remove_dir_all(images_dir);
    let _ = std::fs::remove_dir_all(keystore);
}

#[test]
fn install_sign_then_read_identity_roundtrips_image_meta() {
    let (backend, images_dir, keystore) = backend_with_package("roundtrip", sample_image_meta());

    // Sign bank_b (the inactive/target bank) with the package identity.
    backend.ivd_sign_staged_bank(Bank::B).unwrap();

    // read_installed's identity must round-trip exactly what ImageMeta
    // projected (now mapped to the kind-agnostic FirmwareIdentity).
    let id = backend.verified_bank_identity(Bank::B).unwrap();
    assert_eq!(id.version.as_deref(), Some("1.2.0"));
    assert_eq!(id.ecu_sw_number.as_deref(), Some("VM1-SW-001"));
    assert_eq!(id.system_name.as_deref(), Some("VM1-Linux"));
    assert_eq!(id.spare_part_number.as_deref(), Some("VM1-SPARE-001"));
    assert_eq!(id.supplier_sw_number.as_deref(), Some("SUP-SW-VM1-001"));
    assert_eq!(id.odx_file_id.as_deref(), Some("ODX-VM1-V1"));

    cleanup(&images_dir, &keystore);
}

#[tokio::test]
async fn read_data_serves_identity_dids_from_manifest_not_nv() {
    let (backend, images_dir, keystore) = backend_with_package("readdata", sample_image_meta());

    // Bank_b is the target; make the backend RUN on bank_b so the
    // identity overlay reads the bank we just signed.
    *backend.running_bank.lock().unwrap() = Bank::B;
    backend.ivd_sign_staged_bank(Bank::B).unwrap();

    // NvFwMeta has NO identity fields, so this proves the values come
    // from the signed manifest. Refresh the cache for the running bank.
    {
        let nv = backend.nv.lock().unwrap();
        backend.refresh_did_cache_locked(&nv);
    }

    let want = [
        ("fw_version", "1.2.0"),
        ("ecu_sw_number", "VM1-SW-001"),
        ("supplier_sw_number", "SUP-SW-VM1-001"),
        ("supplier_sw_version", "1.2.0"),
        ("system_name", "VM1-Linux"),
        ("tester_serial", "SOVD-OTA"),
        ("programming_date", "20260604"),
        ("spare_part_number", "VM1-SPARE-001"),
        ("odx_file_id", "ODX-VM1-V1"),
    ];
    for (param, expected) in want {
        let vals = backend.read_data(&[param.to_string()]).await.unwrap();
        assert_eq!(vals.len(), 1, "{param}");
        assert_eq!(
            vals[0].value,
            serde_json::Value::String(expected.to_string()),
            "DID {param} should be served from the signed IVD manifest"
        );
    }

    cleanup(&images_dir, &keystore);
}

#[tokio::test]
async fn read_data_identity_did_unavailable_before_sign() {
    // Before any manifest is signed, the identity DIDs are not in the
    // cache → read_data reports parameter-not-found (they no longer
    // come from NV).
    let (backend, images_dir, keystore) = backend_with_package("presign", sample_image_meta());
    *backend.running_bank.lock().unwrap() = Bank::B;
    // No ivd_sign_staged_bank call; bank_b has a payload file but no
    // manifest yet.
    {
        let nv = backend.nv.lock().unwrap();
        backend.refresh_did_cache_locked(&nv);
    }
    let err = backend
        .read_data(&["fw_version".to_string()])
        .await
        .unwrap_err();
    assert!(matches!(err, BackendError::ParameterNotFound(_)));

    cleanup(&images_dir, &keystore);
}

#[test]
fn tampered_manifest_identity_is_reported_report_only() {
    // Report-only diagnostic read: the identity DIDs come from the on-disk
    // signed manifest WITHOUT an HSM verify, so a tampered-but-decodable
    // manifest is still reported. The served object carries the signature +
    // bytes for the client to verify; the real gate is `verify_bank`.
    let (backend, images_dir, keystore) = backend_with_package("tamper", sample_image_meta());
    backend.ivd_sign_staged_bank(Bank::B).unwrap();

    // Flip a byte INSIDE a string value (the manifest's last field is the
    // identity map; the final byte is string content, so it stays
    // structurally decodable) — the signature no longer matches.
    let mpath = images_dir
        .join("vm1")
        .join("bank_b")
        .join(hsm::ivd::IVD_MANIFEST_FILE);
    let mut bytes = std::fs::read(&mpath).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&mpath, &bytes).unwrap();

    // Report-only: the identity is still served (it decodes).
    assert!(
        backend.verified_bank_identity(Bank::B).is_some(),
        "report-only path serves a decodable manifest's identity"
    );
    assert!(!backend.identity_did_bytes(Bank::B).is_empty());

    cleanup(&images_dir, &keystore);
}

#[tokio::test]
async fn identity_cache_invalidates_on_nv_write() {
    // Cache invalidation rides on NvWriteGuard::drop. Sign with one
    // identity, populate cache, then re-sign the SAME bank with a new
    // identity and trigger an NV write — the cache must reflect the new
    // version, proving install/commit invalidate it.
    let (backend, images_dir, keystore) = backend_with_package("invalidate", sample_image_meta());
    *backend.running_bank.lock().unwrap() = Bank::B;
    backend.ivd_sign_staged_bank(Bank::B).unwrap();
    {
        let nv = backend.nv.lock().unwrap();
        backend.refresh_did_cache_locked(&nv);
    }
    let vals = backend
        .read_data(&["fw_version".to_string()])
        .await
        .unwrap();
    assert_eq!(vals[0].value, serde_json::json!("1.2.0"));

    // Re-sign bank_b with a bumped version (simulating a new install
    // landing on this bank), by swapping the package identity.
    let mut bumped = sample_image_meta();
    bumped.fw_version = [0u8; 32];
    bumped.fw_version[..5].copy_from_slice(b"2.0.0");
    backend
        .packages
        .lock()
        .unwrap()
        .get_mut("pkg-1")
        .unwrap()
        .validated
        .image_meta = bumped;
    backend.ivd_sign_staged_bank(Bank::B).unwrap();

    // Any NV write refreshes the cache via NvWriteGuard::drop.
    {
        let mut guard = backend.nv_write().unwrap();
        let mut boot = guard.read_boot_state().unwrap();
        let _ = guard.write_boot_state(&mut boot);
    }

    let vals = backend
        .read_data(&["fw_version".to_string()])
        .await
        .unwrap();
    assert_eq!(
        vals[0].value,
        serde_json::json!("2.0.0"),
        "cache must reflect the re-signed manifest identity after an NV write"
    );

    cleanup(&images_dir, &keystore);
}

// -----------------------------------------------------------------
// Vendor data parameter: x-ota-installed-manifest
// -----------------------------------------------------------------

#[tokio::test]
async fn installed_manifest_param_listed_and_read_when_committed() {
    let (backend, images_dir, keystore) = backend_with_package("ivdread", sample_image_meta());
    // Run on bank_b (the bank we sign) so the committed manifest is the
    // running one the vendor param serves.
    *backend.running_bank.lock().unwrap() = Bank::B;
    backend.ivd_sign_staged_bank(Bank::B).unwrap();

    // list_parameters advertises the vendor param (IdentData, read-only).
    let params = backend.list_parameters().await.unwrap();
    let p = params
        .iter()
        .find(|p| p.id == INSTALLED_MANIFEST_PARAM_ID)
        .expect("x-ota-installed-manifest must be listed when a manifest exists");
    assert!(p.read_only);
    assert_eq!(p.category, Some(DataCategory::IdentData));
    assert!(p.did.is_none());

    // C-031: with a committed manifest the F187–F19E SW-identity DIDs are
    // listed (they read back from the manifest overlay) AND read 200 — so
    // list and read agree on a flashed bank. fw_version (F189) stands in.
    // Refresh the cache the way the real flash flow does (every
    // finalize/commit/ecu_reset NV write triggers `NvWriteGuard::drop`),
    // since this test signs the bank directly without an NV write.
    {
        let nv = backend.nv.lock().unwrap();
        backend.refresh_did_cache_locked(&nv);
    }
    let fw = params
        .iter()
        .find(|p| p.id == "fw_version")
        .expect("fw_version must be listed when a manifest exists");
    assert_eq!(fw.did.as_deref(), Some("F189"));
    let read = backend
        .read_data(&["fw_version".to_string()])
        .await
        .expect("listed identity DID must read back");
    assert_eq!(read[0].value, serde_json::json!("1.2.0"));

    // read_data returns the structured JSON in `value`.
    let vals = backend
        .read_data(&[INSTALLED_MANIFEST_PARAM_ID.to_string()])
        .await
        .unwrap();
    assert_eq!(vals.len(), 1);
    let v = &vals[0].value;

    // gen + identity come straight from the signed manifest.
    assert_eq!(v["ivd_version"], serde_json::json!(3));
    assert_eq!(v["identity"]["version"], serde_json::json!("1.2.0"));
    assert_eq!(
        v["identity"]["ecu_sw_number"],
        serde_json::json!("VM1-SW-001")
    );
    assert_eq!(v["identity"]["system_name"], serde_json::json!("VM1-Linux"));

    // files[]: each entry has path + lowercase-hex sha256 (64 chars).
    let files = v["files"].as_array().expect("files array");
    assert!(files
        .iter()
        .any(|f| f["path"] == serde_json::json!("rootfs.img")));
    for f in files {
        let sha = f["sha256"].as_str().expect("sha256 hex string");
        assert_eq!(sha.len(), 64, "sha256 must be 32-byte lowercase hex");
        assert!(sha
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    // The two base64 fields decode and re-verify against the HSM,
    // proving they're the exact signed artefacts (downstream re-verify).
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let sig = b64
        .decode(v["signature_b64"].as_str().unwrap())
        .expect("signature_b64 decodes");
    let mbytes = b64
        .decode(v["manifest_b64"].as_str().unwrap())
        .expect("manifest_b64 decodes");
    // manifest_b64 must equal the on-disk signed bytes.
    let on_disk = std::fs::read(
        images_dir
            .join("vm1")
            .join("bank_b")
            .join(hsm::ivd::IVD_MANIFEST_FILE),
    )
    .unwrap();
    assert_eq!(mbytes, on_disk);
    // Re-verify the signature over the manifest bytes via the HSM.
    let ok = hsm::HsmCryptoProvider::verify(
        &**backend.hsm_crypto.as_ref().unwrap(),
        hsm::KeyRole::IvdSigning.handle(),
        &mbytes,
        &sig,
    )
    .unwrap();
    assert!(
        ok,
        "decoded signature must verify over decoded manifest bytes"
    );

    cleanup(&images_dir, &keystore);
}

#[tokio::test]
async fn installed_manifest_param_absent_and_404_without_manifest() {
    // No ivd_sign_staged_bank call → the running bank has a payload file
    // but no signed manifest yet (mirrors no-HSM smoke / never-flashed).
    let (backend, images_dir, keystore) = backend_with_package("ivdnone", sample_image_meta());
    *backend.running_bank.lock().unwrap() = Bank::B;

    // Not advertised.
    let params = backend.list_parameters().await.unwrap();
    assert!(
        !params.iter().any(|p| p.id == INSTALLED_MANIFEST_PARAM_ID),
        "vendor param must be absent when no committed manifest exists"
    );

    // C-031: the manifest-sourced SW-identity DIDs are likewise absent
    // (they'd 404 on read), while a hardware/factory DID stays listed.
    assert!(
        !params.iter().any(|p| is_identity_did(
            u16::from_str_radix(p.did.as_deref().unwrap_or(""), 16).unwrap_or(0)
        )),
        "no manifest-gated identity DID may be listed without a committed manifest"
    );
    assert!(
        params.iter().any(|p| p.id == "serial_number"),
        "hardware/factory serial_number must remain listed without a manifest"
    );

    // Read 404s (EntityNotFound → HTTP 404).
    let err = backend
        .read_data(&[INSTALLED_MANIFEST_PARAM_ID.to_string()])
        .await
        .unwrap_err();
    assert!(
        matches!(err, BackendError::EntityNotFound(_)),
        "expected EntityNotFound (404), got {err:?}"
    );
    assert_eq!(err.status_code(), 404);

    cleanup(&images_dir, &keystore);
}

#[tokio::test]
async fn installed_manifest_param_reports_even_when_signature_would_not_verify() {
    // Report-only path: the diagnostic read surfaces what the bank is
    // supposed to have installed and hands the client the raw bytes +
    // signature to verify independently. It does NOT call into the HSM, so
    // a manifest whose signature would FAIL an HSM verify (here: a flipped
    // byte) is still served — the served `manifest_b64` carries the exact
    // tampered on-disk bytes so a `--pubkey` client catches the mismatch
    // itself. The real on-device gate stays in `verify_bank`.
    let (backend, images_dir, keystore) = backend_with_package("ivdtamper", sample_image_meta());
    *backend.running_bank.lock().unwrap() = Bank::B;
    backend.ivd_sign_staged_bank(Bank::B).unwrap();

    // Flip a byte inside the signed manifest CBOR — still structurally
    // decodable, but the signature no longer matches it.
    let mpath = images_dir
        .join("vm1")
        .join("bank_b")
        .join(hsm::ivd::IVD_MANIFEST_FILE);
    let mut bytes = std::fs::read(&mpath).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&mpath, &bytes).unwrap();

    // Invalidate the cache (an NV write would normally do this) so the
    // re-read hits disk and sees the tampered bytes.
    {
        let nv = backend.nv.lock().unwrap();
        backend.refresh_did_cache_locked(&nv);
    }

    // It is still listed (report-only — present + decodable).
    let params = backend.list_parameters().await.unwrap();
    assert!(
        params.iter().any(|p| p.id == INSTALLED_MANIFEST_PARAM_ID),
        "report-only: param advertised whenever the manifest decodes"
    );

    // And it is served — NOT 404'd.
    let vals = backend
        .read_data(&[INSTALLED_MANIFEST_PARAM_ID.to_string()])
        .await
        .expect("report-only read must succeed even with a bad signature");
    assert_eq!(vals.len(), 1);
    let v = &vals[0].value;

    // The served manifest_b64 is exactly the tampered on-disk bytes — the
    // client re-verifies these against `--pubkey` and detects the tamper.
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let mbytes = b64
        .decode(v["manifest_b64"].as_str().unwrap())
        .expect("manifest_b64 decodes");
    let on_disk = std::fs::read(&mpath).unwrap();
    assert_eq!(
        mbytes, on_disk,
        "served bytes are the raw on-disk (tampered) manifest"
    );
    // Prove the HSM verify over the served artefacts now FAILS — i.e. the
    // client's independent check would reject it.
    let sig = b64
        .decode(v["signature_b64"].as_str().unwrap())
        .expect("signature_b64 decodes");
    let ok = hsm::HsmCryptoProvider::verify(
        &**backend.hsm_crypto.as_ref().unwrap(),
        hsm::KeyRole::IvdSigning.handle(),
        &mbytes,
        &sig,
    )
    .unwrap();
    assert!(
        !ok,
        "served (tampered) bytes must NOT verify — the client gate catches it"
    );

    cleanup(&images_dir, &keystore);
}

/// A `BankActivator` that always fails — drives the finalize rollback path.
struct FailingActivator;
impl machine_mgr::BankActivator for FailingActivator {
    fn activate(
        &self,
        _bank_dir: &Path,
    ) -> Result<(), machine_mgr::bank_activator::BankActivatorError> {
        Err(machine_mgr::bank_activator::BankActivatorError::Failed(
            "synthetic activation failure".into(),
        ))
    }
}

/// When the bank provider's `activate` fails during finalize (the activator
/// errors), the engine must (a) surface the error and (b) roll NV back to
/// the previously-committed bank. The activator runs before the boot
/// selector is sealed, so a failure leaves the activation un-recorded.
#[tokio::test]
async fn finalize_activation_failure_rolls_back() {
    let images_dir = std::env::temp_dir().join("component-mgr-activate-fail-img");
    let _ = std::fs::remove_dir_all(&images_dir);
    std::fs::create_dir_all(&images_dir).unwrap();

    // NV in the post-install trial state: active_bank flipped to B,
    // committed=false (exactly what `install_precomputed` leaves behind).
    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    let idx = slots::VM1.as_index();
    boot.banks[idx].active_bank = Bank::B;
    boot.banks[idx].committed = false;
    nv.write_boot_state(&mut boot).unwrap();
    let nv = Arc::new(Mutex::new(nv));

    // Stage payloads in bank_b (the just-installed bank).
    let set_dir = images_dir.join("vm1");
    let bank_b = set_dir.join("bank_b");
    std::fs::create_dir_all(&bank_b).unwrap();
    std::fs::write(bank_b.join("rootfs.img"), b"new bank bytes").unwrap();

    let backend = ComponentBackend::with_options(
        slots::VM1,
        nv.clone(),
        Arc::new(NoopManifest),
        ComponentConfig::default(),
        None,
        Some(images_dir.clone()),
        None,
    )
    .with_bank_activator(Arc::new(FailingActivator));

    // (a) finalize must surface the activation failure.
    let err = backend.finalize_flash().await.unwrap_err();
    assert!(
        err.to_string().contains("bank activation failed"),
        "expected activation-failure error, got: {err}"
    );

    // (b) NV rolled back to the previously-committed bank (A), committed.
    {
        let nv_guard = nv.lock().unwrap();
        let state = nv_guard.read_boot_state().unwrap();
        assert_eq!(
            state.banks[idx].active_bank,
            Bank::A,
            "NV active_bank must roll back to A after failed activation"
        );
        assert!(
            state.banks[idx].committed,
            "rollback must leave the bank committed"
        );
    }

    let _ = std::fs::remove_dir_all(&images_dir);
}

/// B5 regression: a flash that lands on the session-less *legacy* path while
/// the bank set is in trial mode must be refused (`Busy`) *before* it touches
/// any bank — it must never wipe the committed rollback bank. Without the
/// `ensure_flash_can_start()` guard in the legacy branch of
/// `receive_package_stream`, the path resolved the target to the committed
/// bank (`active.other()`) and `prepare_target_bank_dir` wiped it.
#[tokio::test]
async fn legacy_upload_in_trial_is_refused_without_wiping_committed_bank() {
    let images_dir = std::env::temp_dir().join("component-mgr-b5-trial-legacy-img");
    let _ = std::fs::remove_dir_all(&images_dir);
    std::fs::create_dir_all(&images_dir).unwrap();

    // Trial state: active=B, committed=false → the committed (rollback) bank
    // is A = active.other(), which the buggy legacy path would target+wipe.
    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    let idx = slots::VM1.as_index();
    boot.banks[idx].active_bank = Bank::B;
    boot.banks[idx].committed = false;
    nv.write_boot_state(&mut boot).unwrap();
    let nv = Arc::new(Mutex::new(nv));

    // Sentinel in the committed bank (A) that must survive.
    let bank_a = images_dir.join("vm1").join("bank_a");
    std::fs::create_dir_all(&bank_a).unwrap();
    let sentinel = bank_a.join("rootfs.img");
    std::fs::write(&sentinel, b"committed rollback bytes").unwrap();

    let backend = ComponentBackend::with_options(
        slots::VM1,
        nv,
        Arc::new(NoopManifest),
        ComponentConfig::default(),
        None,
        Some(images_dir.clone()),
        None,
    );

    // No flash session → session-less legacy branch. The guard fires before
    // the stream is read, so an empty stream is sufficient.
    let stream: PackageStream = Box::pin(futures::stream::iter(Vec::<
        Result<bytes::Bytes, Box<dyn std::error::Error + Send + Sync>>,
    >::new()));
    let err = backend
        .receive_package_stream(stream, None)
        .await
        .expect_err("legacy upload in trial mode must be refused");
    assert!(
        matches!(err, BackendError::Busy(_)),
        "expected Busy (trial mode), got: {err:?}"
    );

    // The committed rollback bank must be untouched.
    assert!(
        sentinel.exists(),
        "committed bank A must NOT be wiped by a refused trial-mode flash"
    );
    assert_eq!(
        std::fs::read(&sentinel).unwrap(),
        b"committed rollback bytes",
        "committed bank contents must be intact"
    );

    let _ = std::fs::remove_dir_all(&images_dir);
}
