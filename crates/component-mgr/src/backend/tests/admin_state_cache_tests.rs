// ===========================================================================
// The derived admin-disable state: a derivation that raced a clear is dropped
// ===========================================================================
use super::super::*;
use crate::manifest_provider::ManifestError;
use hsm_sim_backend::SimHsm;
use nv_store::block::MemBlockDevice;
use nv_store::slots;
use nv_store::store::MIN_NV_DEVICE_SIZE;

/// The enact never validates a SUIT envelope here — it is called directly.
struct NoopManifest;
impl ManifestProvider for NoopManifest {
    fn validate(&self, _d: &[u8], _m: u32) -> Result<ValidatedFirmware, ManifestError> {
        Err(ManifestError::ParseError(
            "unused in admin-state cache tests".into(),
        ))
    }
}

struct OkDeactivator;
impl machine_mgr::Deactivator for OkDeactivator {
    fn deactivate(&self) -> Result<machine_mgr::DeactivateOutcome, machine_mgr::DeactivateError> {
        Ok(machine_mgr::DeactivateOutcome {
            reboot_required: false,
        })
    }
}

/// A vm1 backend that can enact a disable for real: an on-disk `images_dir`
/// under `tmp`, a provisioned SimHsm (provisioning authority + crypto
/// handle), a deactivator, and an installed-firmware gen (1) on the serving
/// bank, A.
fn disableable_backend(tmp: &Path) -> ComponentBackend<MemBlockDevice> {
    use hsm::payload::*;
    let ks = tmp.join("keystore");
    std::fs::create_dir_all(&ks).unwrap();
    SimHsm::new(ks.clone())
        .write_keystore(&HsmKeystore {
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
    std::fs::write(ks.join("provision_state"), b"1\n").unwrap();

    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    nv.write_boot_state(&mut NvBootState::default()).unwrap();
    let mut meta = NvFwMeta {
        gen: 1,
        ..Default::default()
    };
    nv.write_fw_meta(slots::VM1, Bank::A, &mut meta).unwrap();
    let hsm: Arc<Mutex<dyn hsm::HsmProvider>> = Arc::new(Mutex::new(SimHsm::new(ks.clone())));
    ComponentBackend::with_options(
        slots::VM1,
        Arc::new(Mutex::new(nv)),
        Arc::new(NoopManifest),
        ComponentConfig::default(),
        None,
        Some(tmp.join("images")),
        Some(hsm),
    )
    .with_hsm_crypto(Arc::new(SimHsm::new(ks)))
    .with_deactivator(Arc::new(OkDeactivator))
}

/// Observe the epoch, clear, store: the store is dropped. Observe and store
/// with no clear between: it lands.
#[test]
fn a_store_from_a_stale_epoch_is_dropped() {
    let mut cache = AdminStateCache::default();

    let observed = cache.epoch;
    cache.clear();
    cache.store_if_epoch(observed, Bank::A, false);
    assert_eq!(cache.value, None, "a derivation older than the clear");

    let observed = cache.epoch;
    cache.store_if_epoch(observed, Bank::A, true);
    assert_eq!(cache.value, Some((Bank::A, true)), "no clear since: stored");
}

/// The race the epoch closes, driven through the backend: a reader misses
/// and derives "enabled" just before a disable lands, and stores only after
/// the enact's clear. The store is dropped, so the next read sees the
/// sentinel instead of the stale answer.
#[tokio::test]
async fn enact_invalidates_a_miss_in_flight() {
    let tmp = tempfile::tempdir().unwrap();
    let b = disableable_backend(tmp.path());

    // A reader misses: it observes the epoch and derives "enabled"…
    let observed = b.admin_disabled_cache.lock().unwrap().epoch;
    // …the disable lands meanwhile…
    b.enact_disable_manifest().await.expect("disable enacted");
    // …and only then does the reader store what it derived.
    b.admin_disabled_cache
        .lock()
        .unwrap()
        .store_if_epoch(observed, Bank::A, false);

    assert!(
        b.admin_disabled(),
        "the stale store was dropped; the sentinel reads through"
    );
}
