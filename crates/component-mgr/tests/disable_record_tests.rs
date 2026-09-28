//! Integration test: the administrative-disable record of `IvdBankProvider` —
//! the signed IVD sentinel `write_disabled_record` persists and
//! `disabled_record` reads back — driven through the public `BankProvider`
//! surface over a sim-HSM, plus the single-bank `prepare_target` that must
//! leave that record in place.
//!
//! The keystore fixture reproduces `tests/partition_bank.rs`'s
//! `provisioned_keystore` (an integration test can't reach another test
//! crate's helpers).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use nv_store::block::MemBlockDevice;
use nv_store::slots;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::{Bank, NvBootState};

use machine_mgr::bank_provider::{BankError, BankProvider, FirmwareIdentity};

use component_mgr::bank_provider::{bank_dir_name, IvdBankProvider};

/// Provision the IVD-signing slot in a fresh keystore dir. Reproduces
/// `partition_bank.rs`'s `provisioned_keystore`.
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

/// A `vm1` provider over fresh NV (every set's active bank = A, so an A/B
/// provider targets B). `keystore` wires a SimHsm over that dir as both the
/// provisioning authority and the crypto handle; `None` wires no HSM at all.
fn provider(
    images_dir: Option<PathBuf>,
    single_bank: bool,
    keystore: Option<&Path>,
) -> IvdBankProvider<MemBlockDevice> {
    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    nv.write_boot_state(&mut NvBootState::default()).unwrap();
    let hsm = keystore.map(|ks| -> Arc<Mutex<dyn hsm::HsmProvider>> {
        Arc::new(Mutex::new(hsm_sim_backend::SimHsm::new(ks.to_path_buf())))
    });
    let p = IvdBankProvider::new(
        Arc::new(Mutex::new(nv)),
        slots::VM1,
        single_bank,
        images_dir,
        "vm1".into(),
        hsm,
        None,
        None,
    );
    match keystore {
        Some(ks) => p.with_hsm_crypto(Arc::new(hsm_sim_backend::SimHsm::new(ks.to_path_buf()))),
        None => p,
    }
}

fn identity() -> FirmwareIdentity {
    FirmwareIdentity {
        version: Some("1.2.0".into()),
        ecu_sw_number: Some("VM1-SW-001".into()),
        ..Default::default()
    }
}

/// Stage `kernel` into `bank` and seal it: a real signed inventory at `gen`.
fn seal_real_bank(p: &IvdBankProvider<MemBlockDevice>, bank_dir: &Path, bank: Bank, gen: u64) {
    std::fs::create_dir_all(bank_dir).unwrap();
    std::fs::write(bank_dir.join("kernel"), b"kernel bytes").unwrap();
    p.seal(bank, identity(), gen, &["kernel".to_string()])
        .unwrap();
    assert!(
        bank_dir.join(hsm::ivd::IVD_SIGNATURE_FILE).exists(),
        "precondition: the bank is sealed"
    );
}

/// machine-contract repeats the sentinel's path because it may not depend on
/// `hsm`; this is the pin that keeps the two equal.
#[test]
fn sentinel_path_constants_agree() {
    assert_eq!(
        hsm::ivd::IVD_DISABLED_RECORD_PATH,
        machine_mgr::DISABLED_RECORD_PATH
    );
}

/// `seal` skips an unsignable bank with a warning; a disable must not. No HSM,
/// an unprovisioned HSM and no `images_dir` each refuse with an `Err` and write
/// nothing — and the same provider shape with a provisioned HSM succeeds, so no
/// refusal is a fixture fault.
#[test]
fn write_disabled_record_refuses_without_hsm_or_images_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let images = tmp.path().join("images");
    let bank_dir = images.join("vm1").join(bank_dir_name(Bank::A));
    let refusal = |r: Result<(), BankError>| match r {
        Err(BankError::Failed(msg)) => msg,
        other => panic!("expected a Failed refusal, got {other:?}"),
    };

    let p = provider(Some(images.clone()), false, None);
    let msg = refusal(p.write_disabled_record(Bank::A, 3));
    assert!(msg.contains("no HSM provider"), "got: {msg}");
    assert!(!bank_dir.exists(), "a refused disable writes nothing");

    let unprovisioned = tmp.path().join("empty-keystore");
    std::fs::create_dir_all(&unprovisioned).unwrap();
    let p = provider(Some(images.clone()), false, Some(&unprovisioned));
    let msg = refusal(p.write_disabled_record(Bank::A, 3));
    assert!(msg.contains("HSM not provisioned"), "got: {msg}");
    assert!(!bank_dir.exists(), "a refused disable writes nothing");

    let ks = provisioned_keystore(tmp.path());
    let p = provider(None, false, Some(&ks));
    let msg = refusal(p.write_disabled_record(Bank::A, 3));
    assert!(msg.contains("no images_dir"), "got: {msg}");

    // Control: provisioned HSM + images_dir → persisted.
    provider(Some(images.clone()), false, Some(&ks))
        .write_disabled_record(Bank::A, 3)
        .unwrap();
    assert!(bank_dir.join(hsm::ivd::IVD_MANIFEST_FILE).exists());
    assert!(bank_dir.join(hsm::ivd::IVD_SIGNATURE_FILE).exists());
}

/// Every record that is not a verified sentinel reads `Ok(None)`: no record at
/// all, a real sealed inventory, and a sentinel whose signature no longer
/// verifies (that one with a warn, and no panic).
#[test]
fn disabled_record_reads_none_for_missing_real_and_unsigned() {
    let tmp = tempfile::tempdir().unwrap();
    let ks = provisioned_keystore(tmp.path());
    let images = tmp.path().join("images");
    let bank_dir = images.join("vm1").join(bank_dir_name(Bank::B));
    let p = provider(Some(images.clone()), false, Some(&ks));

    assert_eq!(p.disabled_record(Bank::B).unwrap(), None, "no record");

    seal_real_bank(&p, &bank_dir, Bank::B, 5);
    assert_eq!(p.disabled_record(Bank::B).unwrap(), None, "real inventory");

    p.write_disabled_record(Bank::B, 6).unwrap();
    assert_eq!(p.disabled_record(Bank::B).unwrap(), Some(6), "control");
    // Flip the signature's last byte: still well-formed DER, no longer valid.
    let sig = bank_dir.join(hsm::ivd::IVD_SIGNATURE_FILE);
    let mut bytes = std::fs::read(&sig).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&sig, &bytes).unwrap();
    assert_eq!(p.disabled_record(Bank::B).unwrap(), None, "bad signature");
}

/// Disabling a sealed bank in place: the sentinel reads back as its gen, keeps
/// the replaced record's identity, leaves the bank's images where they are,
/// and the launch gate refuses the bank as `AdminDisabled`.
#[test]
fn disabled_record_reads_gen_of_a_valid_sentinel() {
    let tmp = tempfile::tempdir().unwrap();
    let ks = provisioned_keystore(tmp.path());
    let images = tmp.path().join("images");
    let bank_dir = images.join("vm1").join(bank_dir_name(Bank::B));
    let p = provider(Some(images.clone()), false, Some(&ks));
    seal_real_bank(&p, &bank_dir, Bank::B, 5);

    p.write_disabled_record(Bank::B, 6).unwrap();
    assert_eq!(p.disabled_record(Bank::B).unwrap(), Some(6));

    let fw = p.read_installed(Bank::B).unwrap();
    assert!(fw.is_disabled_record());
    assert_eq!(fw.gen, 6);
    assert_eq!(fw.identity.version.as_deref(), Some("1.2.0"));
    assert_eq!(
        std::fs::read(bank_dir.join("kernel")).unwrap(),
        b"kernel bytes"
    );

    let crypto = hsm_sim_backend::SimHsm::new(ks);
    let pins = hsm::ivd::VerifyPins {
        expected_install_gen: Some(6),
        min_committed_gen: Some(5),
    };
    match hsm::ivd::verify_bank_crypto(&crypto, &bank_dir, pins) {
        Err(hsm::ivd::IvdError::AdminDisabled { gen }) => assert_eq!(gen, 6),
        other => panic!("expected AdminDisabled, got {other:?}"),
    }
}

/// A single bank's `prepare_target` wipes the LIVE bank at flash start, so it
/// keeps the IVD pair: a disable survives a flash that never reaches `seal`.
/// An A/B target is the idle sibling and is wiped whole.
#[test]
fn prepare_target_spares_the_ivd_pair_only_for_single_bank() {
    let tmp = tempfile::tempdir().unwrap();
    let ks = provisioned_keystore(tmp.path());

    let images = tmp.path().join("single");
    let p = provider(Some(images.clone()), true, Some(&ks));
    let bank = p.target_bank();
    let bank_dir = images.join("vm1").join(bank_dir_name(bank));
    p.write_disabled_record(bank, 4).unwrap();
    std::fs::write(bank_dir.join("kernel"), b"old kernel").unwrap();
    p.prepare_target(bank).unwrap();
    assert!(!bank_dir.join("kernel").exists(), "payloads are wiped");
    assert_eq!(p.disabled_record(bank).unwrap(), Some(4), "sentinel kept");

    let images = tmp.path().join("ab");
    let p = provider(Some(images.clone()), false, Some(&ks));
    let bank = p.target_bank();
    let bank_dir = images.join("vm1").join(bank_dir_name(bank));
    p.write_disabled_record(bank, 4).unwrap();
    std::fs::write(bank_dir.join("kernel"), b"old kernel").unwrap();
    p.prepare_target(bank).unwrap();
    assert!(!bank_dir.join("kernel").exists(), "payloads are wiped");
    assert!(!bank_dir.join(hsm::ivd::IVD_MANIFEST_FILE).exists());
    assert!(!bank_dir.join(hsm::ivd::IVD_SIGNATURE_FILE).exists());
    assert_eq!(p.disabled_record(bank).unwrap(), None);
}
