#![allow(clippy::field_reassign_with_default)]

use nv_store::block::MemBlockDevice;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::*;

use crate::did::*;
use crate::ota::*;

fn make_nv() -> NvStore<MemBlockDevice> {
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    // Initialize boot state (all committed on Bank A)
    let mut state = NvBootState::default();
    nv.write_boot_state(&mut state).unwrap();
    nv
}

fn str_arr<const N: usize>(s: &str) -> [u8; N] {
    let mut arr = [0u8; N];
    let len = s.len().min(N);
    arr[..len].copy_from_slice(&s.as_bytes()[..len]);
    arr
}

// ============================================================
// DID Resolution tests
// ============================================================

#[test]
fn did_factory_serial_number() {
    let mut nv = make_nv();
    let mut factory = NvFactory::default();
    factory.serial_number = str_arr("ECU-001");
    nv.write_factory(&mut factory).unwrap();

    let val = read_did(&nv, BankSet::Vm1, DID_SERIAL_NUMBER, None);
    assert_eq!(val.as_str(), Some("ECU-001"));
}

#[test]
fn did_factory_vin() {
    let mut nv = make_nv();
    let mut factory = NvFactory::default();
    factory.vin = str_arr("WDB1234567890ABCD");
    nv.write_factory(&mut factory).unwrap();

    let val = read_did(&nv, BankSet::Vm1, DID_VIN, None);
    assert_eq!(val.as_str(), Some("WDB1234567890ABCD"));
}

#[test]
fn did_fw_version_not_served_from_nv() {
    // F189 (fw_version) and the other SW-identity DIDs moved to the
    // signed IVD manifest. The NV-only `read_did` path no longer serves
    // them (it can't authenticate the manifest); the VmBackend layer
    // does, from a verified IvdIdentity (covered in backend.rs tests).
    let mut nv = make_nv();
    let mut meta = NvFwMeta::default();
    meta.fw_seq = 21;
    nv.write_fw_meta(BankSet::Vm1, Bank::A, &mut meta).unwrap();

    assert_eq!(
        read_did(&nv, BankSet::Vm1, DID_FW_VERSION, None),
        DidValue::NotFound
    );
}

#[test]
fn did_fw_meta_security_ver_reads_active_bank() {
    // fw_secver (a KEPT NvFwMeta field, surfaced via DID_CURRENT_SECURITY_VER)
    // resolves against the active bank — proving per-bank NV resolution
    // still works for the fields that stayed in NvFwMeta.
    let mut nv = make_nv();

    let mut meta_a = NvFwMeta::default();
    meta_a.fw_secver = 1;
    nv.write_fw_meta(BankSet::Vm1, Bank::A, &mut meta_a)
        .unwrap();

    let mut meta_b = NvFwMeta::default();
    meta_b.fw_secver = 2;
    nv.write_fw_meta(BankSet::Vm1, Bank::B, &mut meta_b)
        .unwrap();

    // Active bank is A → secver 1.
    let val = read_did(&nv, BankSet::Vm1, DID_CURRENT_SECURITY_VER, None);
    assert_eq!(val, DidValue::Bytes(1u32.to_le_bytes().to_vec()));

    // Switch to B → secver 2.
    let mut state = nv.read_boot_state().unwrap();
    state.banks[1].active_bank = Bank::B;
    nv.write_boot_state(&mut state).unwrap();

    let val = read_did(&nv, BankSet::Vm1, DID_CURRENT_SECURITY_VER, None);
    assert_eq!(val, DidValue::Bytes(2u32.to_le_bytes().to_vec()));
}

#[test]
fn did_runtime_serves_identity_did() {
    // A runtime-written value for an identity DID (source 1) is served
    // directly — the NV-only path otherwise returns NotFound for these
    // now that they live in the signed manifest.
    let mut nv = make_nv();

    write_did(&mut nv, BankSet::Vm1, DID_TESTER_SERIAL, b"TOOL-B").unwrap();

    let val = read_did(&nv, BankSet::Vm1, DID_TESTER_SERIAL, None);
    assert_eq!(val.as_str(), Some("TOOL-B"));
}

#[test]
fn did_runtime_write_and_read() {
    let mut nv = make_nv();

    let ok = write_did(&mut nv, BankSet::Vm1, 0xFD10, b"hello").unwrap();
    assert!(ok);

    let val = read_did(&nv, BankSet::Vm1, 0xFD10, None);
    assert_eq!(val, DidValue::Bytes(b"hello".to_vec()));
}

#[test]
fn did_runtime_update_existing() {
    let mut nv = make_nv();

    write_did(&mut nv, BankSet::Vm1, 0xFD10, b"v1").unwrap();
    write_did(&mut nv, BankSet::Vm1, 0xFD10, b"v2").unwrap();

    let val = read_did(&nv, BankSet::Vm1, 0xFD10, None);
    assert_eq!(val, DidValue::Bytes(b"v2".to_vec()));
}

#[test]
fn did_runtime_full() {
    let mut nv = make_nv();

    // Fill all 20 slots
    for i in 0..MAX_DIDS as u16 {
        let ok = write_did(&mut nv, BankSet::Vm1, 0xFD10 + i, &[i as u8]).unwrap();
        assert!(ok);
    }

    // 21st should fail
    let ok = write_did(&mut nv, BankSet::Vm1, 0xFDFF, b"overflow").unwrap();
    assert!(!ok);
}

#[test]
fn did_dynamic_active_bank() {
    let mut nv = make_nv();

    let val = read_did(&nv, BankSet::Vm1, DID_ACTIVE_BANK, None);
    assert_eq!(val, DidValue::Bytes(vec![b'A']));

    let mut state = nv.read_boot_state().unwrap();
    state.banks[1].active_bank = Bank::B;
    nv.write_boot_state(&mut state).unwrap();

    let val = read_did(&nv, BankSet::Vm1, DID_ACTIVE_BANK, None);
    assert_eq!(val, DidValue::Bytes(vec![b'B']));
}

#[test]
fn did_dynamic_committed() {
    let mut nv = make_nv();

    let val = read_did(&nv, BankSet::Vm1, DID_COMMITTED, None);
    assert_eq!(val, DidValue::Bytes(vec![1])); // true

    let mut state = nv.read_boot_state().unwrap();
    state.banks[1].committed = false;
    nv.write_boot_state(&mut state).unwrap();

    let val = read_did(&nv, BankSet::Vm1, DID_COMMITTED, None);
    assert_eq!(val, DidValue::Bytes(vec![0])); // false
}

#[test]
fn did_dynamic_security_versions() {
    let mut nv = make_nv();

    let mut meta = NvFwMeta::default();
    meta.fw_secver = 5;
    meta.min_security_ver = 3;
    nv.write_fw_meta(BankSet::Vm1, Bank::A, &mut meta).unwrap();

    let val = read_did(&nv, BankSet::Vm1, DID_CURRENT_SECURITY_VER, None);
    assert_eq!(val, DidValue::Bytes(5u32.to_le_bytes().to_vec()));

    let val = read_did(&nv, BankSet::Vm1, DID_MIN_SECURITY_VER, None);
    assert_eq!(val, DidValue::Bytes(3u32.to_le_bytes().to_vec()));
}

#[test]
fn did_not_found() {
    let nv = make_nv();
    let val = read_did(&nv, BankSet::Vm1, 0x1234, None);
    assert_eq!(val, DidValue::NotFound);
}

#[test]
fn did_bank_set_isolation() {
    let mut nv = make_nv();

    write_did(&mut nv, BankSet::Vm1, 0xFD10, b"vm1-data").unwrap();
    write_did(&mut nv, BankSet::Vm2, 0xFD10, b"vm2-data").unwrap();

    let val1 = read_did(&nv, BankSet::Vm1, 0xFD10, None);
    let val2 = read_did(&nv, BankSet::Vm2, 0xFD10, None);
    assert_eq!(val1, DidValue::Bytes(b"vm1-data".to_vec()));
    assert_eq!(val2, DidValue::Bytes(b"vm2-data".to_vec()));
}

// ============================================================
// OTA Install tests
// ============================================================

fn make_image_meta(version: &str, secver: u32) -> ImageMeta {
    let mut meta = ImageMeta::default();
    meta.fw_version = str_arr(version);
    meta.fw_secver = secver;
    meta.fw_seq = secver;
    meta
}

#[test]
fn ota_install_basic() {
    let mut nv = make_nv();
    let image = b"firmware-v2-image-data";
    let meta = make_image_meta("2.0", 2);

    let result = install(&mut nv, BankSet::Vm1, image, &meta, false).unwrap();
    assert_eq!(result.target_bank, Bank::B); // was on A, target is B

    // Boot state: trial on B
    let state = nv.read_boot_state().unwrap();
    assert_eq!(state.banks[1].active_bank, Bank::B);
    assert!(!state.banks[1].committed);
    assert_eq!(state.banks[1].boot_count, 0);

    // FW Meta written for B. Identity (version "2.0") lives in the IVD
    // manifest now; NvFwMeta carries fw_seq/secver/hash.
    let fw = nv.read_fw_meta(BankSet::Vm1, Bank::B).unwrap();
    assert_eq!(fw.fw_seq, 2);
    assert_eq!(fw.fw_secver, 2);
    assert_eq!(fw.image_sha256, result.image_sha256);
}

#[test]
fn ota_install_rejects_if_trial() {
    let mut nv = make_nv();

    // Put VM1 in trial
    let mut state = nv.read_boot_state().unwrap();
    state.banks[1].committed = false;
    nv.write_boot_state(&mut state).unwrap();

    let result = install(&mut nv, BankSet::Vm1, b"img", &ImageMeta::default(), false);
    assert_eq!(result.unwrap_err(), OtaError::InTrial);
}

#[test]
fn ota_install_rejects_low_security_version() {
    let mut nv = make_nv();

    // Set min_security_ver = 5 on current bank
    let mut meta = NvFwMeta::default();
    meta.min_security_ver = 5;
    nv.write_fw_meta(BankSet::Vm1, Bank::A, &mut meta).unwrap();

    // Try to install secver=3 — should be rejected
    let img_meta = make_image_meta("old", 3);
    let result = install(&mut nv, BankSet::Vm1, b"img", &img_meta, false);
    assert_eq!(
        result.unwrap_err(),
        OtaError::SecurityVersionTooLow { image: 3, floor: 5 }
    );
}

#[test]
fn ota_install_preserves_min_security_ver() {
    let mut nv = make_nv();

    // Active bank A has floor=3
    let mut meta = NvFwMeta::default();
    meta.min_security_ver = 3;
    nv.write_fw_meta(BankSet::Vm1, Bank::A, &mut meta).unwrap();

    // Install secver=5 to B
    let img_meta = make_image_meta("2.0", 5);
    install(&mut nv, BankSet::Vm1, b"img", &img_meta, false).unwrap();

    // Target bank B should preserve floor=3 (not raised until commit)
    let fw_b = nv.read_fw_meta(BankSet::Vm1, Bank::B).unwrap();
    assert_eq!(fw_b.min_security_ver, 3);
    assert_eq!(fw_b.fw_secver, 5);
}

#[test]
fn ota_install_copies_runtime() {
    let mut nv = make_nv();

    // Write runtime DID on active bank A
    write_did(&mut nv, BankSet::Vm1, 0xFD10, b"preserved").unwrap();

    // Install to B
    install(
        &mut nv,
        BankSet::Vm1,
        b"img",
        &make_image_meta("2.0", 1),
        false,
    )
    .unwrap();

    // Runtime should have been copied to B
    let runtime_b = nv.read_runtime(BankSet::Vm1, Bank::B).unwrap();
    assert_eq!(runtime_b.did_count, 1);
    assert_eq!(runtime_b.dids[0].did, 0xFD10);
    assert_eq!(&runtime_b.dids[0].data[..9], b"preserved");
}

// ============================================================
// Commit tests
// ============================================================

#[test]
fn commit_basic() {
    let mut nv = make_nv();

    // Install then commit
    install(
        &mut nv,
        BankSet::Vm1,
        b"img",
        &make_image_meta("2.0", 3),
        false,
    )
    .unwrap();
    commit(&mut nv, BankSet::Vm1).unwrap();

    let state = nv.read_boot_state().unwrap();
    assert!(state.banks[1].committed);
    assert_eq!(state.banks[1].active_bank, Bank::B);
    assert_eq!(state.banks[1].boot_count, 0);
}

#[test]
fn commit_raises_anti_rollback_floor() {
    let mut nv = make_nv();

    // Current floor = 1
    let mut meta = NvFwMeta::default();
    meta.min_security_ver = 1;
    nv.write_fw_meta(BankSet::Vm1, Bank::A, &mut meta).unwrap();

    // Install secver=5
    install(
        &mut nv,
        BankSet::Vm1,
        b"img",
        &make_image_meta("2.0", 5),
        false,
    )
    .unwrap();

    // Before commit: floor still 1
    let fw = nv.read_fw_meta(BankSet::Vm1, Bank::B).unwrap();
    assert_eq!(fw.min_security_ver, 1);

    // Commit: floor raised to 5
    commit(&mut nv, BankSet::Vm1).unwrap();
    let fw = nv.read_fw_meta(BankSet::Vm1, Bank::B).unwrap();
    assert_eq!(fw.min_security_ver, 5);
}

#[test]
fn commit_rejects_if_committed() {
    let mut nv = make_nv();
    let result = commit(&mut nv, BankSet::Vm1);
    assert_eq!(result.unwrap_err(), OtaError::AlreadyCommitted);
}

// ============================================================
// Rollback tests
// ============================================================

#[test]
fn rollback_basic() {
    let mut nv = make_nv();

    install(
        &mut nv,
        BankSet::Vm1,
        b"img",
        &make_image_meta("2.0", 1),
        false,
    )
    .unwrap();

    let previous = rollback(&mut nv, BankSet::Vm1).unwrap();
    assert_eq!(previous, Bank::A); // rolled back to A

    let state = nv.read_boot_state().unwrap();
    assert_eq!(state.banks[1].active_bank, Bank::A);
    assert!(state.banks[1].committed);
}

#[test]
fn rollback_rejects_if_committed() {
    let mut nv = make_nv();
    let result = rollback(&mut nv, BankSet::Vm1);
    assert_eq!(result.unwrap_err(), OtaError::NotInTrial);
}

// ============================================================
// Status tests
// ============================================================

#[test]
fn status_committed() {
    let mut nv = make_nv();
    let mut meta = NvFwMeta::default();
    meta.fw_seq = 1;
    meta.fw_secver = 1;
    meta.min_security_ver = 1;
    nv.write_fw_meta(BankSet::Vm1, Bank::A, &mut meta).unwrap();

    let s = status(&nv, BankSet::Vm1).unwrap();
    assert_eq!(s.active_bank, Bank::A);
    assert!(s.committed);
    assert_eq!(s.boot_count, 0);
    assert_eq!(s.fw_secver, Some(1));
    assert_eq!(s.min_security_ver, Some(1));
}

#[test]
fn status_trial() {
    let mut nv = make_nv();
    install(
        &mut nv,
        BankSet::Vm1,
        b"img",
        &make_image_meta("2.0", 3),
        false,
    )
    .unwrap();

    let s = status(&nv, BankSet::Vm1).unwrap();
    assert_eq!(s.active_bank, Bank::B);
    assert!(!s.committed);
    assert_eq!(s.fw_secver, Some(3));
}

// ============================================================
// Full OTA lifecycle tests
// ============================================================

#[test]
fn full_ota_install_commit_then_new_update() {
    let mut nv = make_nv();

    // v1 on bank A (initial)
    let mut meta_a = NvFwMeta::default();
    meta_a.fw_seq = 1;
    meta_a.fw_secver = 1;
    meta_a.min_security_ver = 0;
    nv.write_fw_meta(BankSet::Vm1, Bank::A, &mut meta_a)
        .unwrap();

    // Install v2 → bank B
    install(
        &mut nv,
        BankSet::Vm1,
        b"v2-image",
        &make_image_meta("2.0", 2),
        false,
    )
    .unwrap();
    commit(&mut nv, BankSet::Vm1).unwrap();

    // Now on bank B, committed
    let s = status(&nv, BankSet::Vm1).unwrap();
    assert_eq!(s.active_bank, Bank::B);
    assert!(s.committed);

    // Install v3 → bank A (cycles back)
    install(
        &mut nv,
        BankSet::Vm1,
        b"v3-image",
        &make_image_meta("3.0", 3),
        false,
    )
    .unwrap();

    let s = status(&nv, BankSet::Vm1).unwrap();
    assert_eq!(s.active_bank, Bank::A);
    assert!(!s.committed);

    commit(&mut nv, BankSet::Vm1).unwrap();
    let fw = nv.read_fw_meta(BankSet::Vm1, Bank::A).unwrap();
    assert_eq!(fw.fw_seq, 3); // version "3.0" now lives in the IVD manifest
    assert_eq!(fw.min_security_ver, 3); // floor raised
}

#[test]
fn full_ota_install_rollback_retry() {
    let mut nv = make_nv();

    // Install v2 → B, then rollback to A
    install(
        &mut nv,
        BankSet::Vm1,
        b"bad-img",
        &make_image_meta("2.0", 1),
        false,
    )
    .unwrap();
    rollback(&mut nv, BankSet::Vm1).unwrap();

    let s = status(&nv, BankSet::Vm1).unwrap();
    assert_eq!(s.active_bank, Bank::A);
    assert!(s.committed);

    // Can install again (back to B)
    install(
        &mut nv,
        BankSet::Vm1,
        b"good-img",
        &make_image_meta("2.1", 2),
        false,
    )
    .unwrap();
    commit(&mut nv, BankSet::Vm1).unwrap();

    let s = status(&nv, BankSet::Vm1).unwrap();
    assert_eq!(s.active_bank, Bank::B);
    assert!(s.committed);
}

#[test]
fn full_ota_multiple_bank_sets() {
    let mut nv = make_nv();

    // Update VM1
    install(
        &mut nv,
        BankSet::Vm1,
        b"vm1-v2",
        &make_image_meta("vm1-2.0", 1),
        false,
    )
    .unwrap();
    commit(&mut nv, BankSet::Vm1).unwrap();

    // Update VM2
    install(
        &mut nv,
        BankSet::Vm2,
        b"vm2-v2",
        &make_image_meta("vm2-2.0", 1),
        false,
    )
    .unwrap();
    commit(&mut nv, BankSet::Vm2).unwrap();

    // Both on B, independent
    assert_eq!(status(&nv, BankSet::Vm1).unwrap().active_bank, Bank::B);
    assert_eq!(status(&nv, BankSet::Vm2).unwrap().active_bank, Bank::B);
    assert_eq!(status(&nv, BankSet::HostOs).unwrap().active_bank, Bank::A); // untouched
}

#[test]
fn anti_rollback_blocks_downgrade_after_commit() {
    let mut nv = make_nv();

    // Install v2 secver=5, commit (floor raised to 5)
    install(
        &mut nv,
        BankSet::Vm1,
        b"v2",
        &make_image_meta("2.0", 5),
        false,
    )
    .unwrap();
    commit(&mut nv, BankSet::Vm1).unwrap();

    // Try install v3 with secver=3 — blocked
    let result = install(
        &mut nv,
        BankSet::Vm1,
        b"v3-old",
        &make_image_meta("3.0", 3),
        false,
    );
    assert_eq!(
        result.unwrap_err(),
        OtaError::SecurityVersionTooLow { image: 3, floor: 5 }
    );

    // secver=5 is allowed (equal to floor)
    let result = install(
        &mut nv,
        BankSet::Vm1,
        b"v3-ok",
        &make_image_meta("3.0", 5),
        false,
    );
    assert!(result.is_ok());
}

// ============================================================
// HSM single-bank install tests
// ============================================================

#[test]
fn hsm_install_single_bank() {
    let mut nv = make_nv();

    // Single-bank install: always writes to bank A, committed immediately
    let result = install(
        &mut nv,
        BankSet::Hsm,
        b"hsm-fw",
        &make_image_meta("1.0", 1),
        true,
    )
    .unwrap();
    assert_eq!(result.target_bank, Bank::A);

    // State: committed on bank A, no trial
    let state = nv.read_boot_state().unwrap();
    let hsm = &state.banks[BankSet::Hsm.as_index()];
    assert!(hsm.committed);
    assert_eq!(hsm.active_bank, Bank::A);
    assert_eq!(hsm.boot_count, 0);

    // Anti-rollback floor raised immediately (no separate commit needed)
    let fw = nv.read_fw_meta(BankSet::Hsm, Bank::A).unwrap();
    assert_eq!(fw.min_security_ver, 1);
}

#[test]
fn hsm_install_overwrites_bank_a() {
    let mut nv = make_nv();

    // First install
    install(
        &mut nv,
        BankSet::Hsm,
        b"hsm-v1",
        &make_image_meta("1.0", 1),
        true,
    )
    .unwrap();

    // Second install also goes to bank A (overwrites)
    let result = install(
        &mut nv,
        BankSet::Hsm,
        b"hsm-v2",
        &make_image_meta("2.0", 2),
        true,
    )
    .unwrap();
    assert_eq!(result.target_bank, Bank::A);

    let fw = nv.read_fw_meta(BankSet::Hsm, Bank::A).unwrap();
    assert_eq!(fw.fw_seq, 2); // version "2.0" now lives in the IVD manifest
    assert_eq!(fw.min_security_ver, 2);
}

#[test]
fn hsm_rollback_rejected() {
    let mut nv = make_nv();

    // Single-bank install (committed immediately)
    install(
        &mut nv,
        BankSet::Hsm,
        b"hsm-fw",
        &make_image_meta("1.0", 1),
        true,
    )
    .unwrap();

    // Rollback should fail — already committed
    let result = rollback(&mut nv, BankSet::Hsm);
    assert_eq!(result.unwrap_err(), OtaError::NotInTrial);
}

#[test]
fn hsm_commit_is_noop() {
    let mut nv = make_nv();

    // Single-bank install (already committed)
    install(
        &mut nv,
        BankSet::Hsm,
        b"hsm-fw",
        &make_image_meta("1.0", 1),
        true,
    )
    .unwrap();

    // Commit on already-committed → error (expected: AlreadyCommitted)
    let result = commit(&mut nv, BankSet::Hsm);
    assert_eq!(result.unwrap_err(), OtaError::AlreadyCommitted);
}

// ============================================================
// Boot (IFS boot image — A/B banked, NV slot 4)
// ============================================================

#[test]
fn boot_flash_trial_mode() {
    let mut nv = make_nv();

    // Standard A/B install
    let result = install(
        &mut nv,
        BankSet::HostOs,
        b"boot-v2",
        &make_image_meta("2.0", 1),
        false,
    )
    .unwrap();
    assert_eq!(result.target_bank, Bank::B);

    // Should be in trial mode
    let state = nv.read_boot_state().unwrap();
    let boot = &state.banks[BankSet::HostOs.as_index()];
    assert!(!boot.committed);
    assert_eq!(boot.active_bank, Bank::B);

    // Commit works
    commit(&mut nv, BankSet::HostOs).unwrap();
    let state = nv.read_boot_state().unwrap();
    assert!(state.banks[BankSet::HostOs.as_index()].committed);
}

#[test]
fn boot_rollback_works() {
    let mut nv = make_nv();

    install(
        &mut nv,
        BankSet::HostOs,
        b"boot-v2",
        &make_image_meta("2.0", 1),
        false,
    )
    .unwrap();
    let prev = rollback(&mut nv, BankSet::HostOs).unwrap();
    assert_eq!(prev, Bank::A);

    let state = nv.read_boot_state().unwrap();
    assert!(state.banks[BankSet::HostOs.as_index()].committed);
    assert_eq!(state.banks[BankSet::HostOs.as_index()].active_bank, Bank::A);
}
