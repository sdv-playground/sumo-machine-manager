// Tests construct records via `Default::default()` then mutate fields
// — the struct-init form would mean spelling out every default field
// at every call site for negligible benefit.  Allow at module scope.
#![allow(clippy::field_reassign_with_default)]

use crate::block::{BlockDevice, BlockError, MemBlockDevice};
use crate::store::*;
use crate::types::*;

fn make_store() -> NvStore<MemBlockDevice> {
    NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize))
}

// --- Serialization roundtrip tests ---

#[test]
fn boot_state_roundtrip() {
    let mut store = make_store();
    let mut state = NvBootState {
        write_seq: 0,
        banks: std::array::from_fn(|i| match i {
            0 => BankBootState {
                active_bank: Bank::A,
                committed: true,
                boot_count: 0,
            },
            1 => BankBootState {
                active_bank: Bank::B,
                committed: false,
                boot_count: 7,
            },
            2 => BankBootState {
                active_bank: Bank::A,
                committed: true,
                boot_count: 0,
            },
            _ => BankBootState::default(),
        }),
    };

    store.write_boot_state(&mut state).unwrap();
    let read = store.read_boot_state().unwrap();

    assert_eq!(read.banks[0].active_bank, Bank::A);
    assert!(read.banks[0].committed);
    assert_eq!(read.banks[0].boot_count, 0);

    assert_eq!(read.banks[1].active_bank, Bank::B);
    assert!(!read.banks[1].committed);
    assert_eq!(read.banks[1].boot_count, 7);

    assert_eq!(read.banks[2].active_bank, Bank::A);
    assert!(read.banks[2].committed);
}

#[test]
fn factory_roundtrip() {
    let mut store = make_store();
    let mut factory = NvFactory::default();
    factory.serial_number[..5].copy_from_slice(b"SN001");
    factory.vin[..17].copy_from_slice(b"WDB1234567890ABCD");
    factory.device_type = 42;

    store.write_factory(&mut factory).unwrap();
    let read = store.read_factory().unwrap();

    assert_eq!(&read.serial_number[..5], b"SN001");
    assert_eq!(&read.vin, b"WDB1234567890ABCD");
    assert_eq!(read.device_type, 42);
}

#[test]
fn fw_meta_roundtrip() {
    let mut store = make_store();
    // NvFwMeta carries boot/install state only — SW identity moved to
    // the signed IVD manifest (hsm::ivd::IvdIdentity).
    let mut meta = NvFwMeta::default();
    meta.fw_seq = 10;
    meta.fw_secver = 3;
    meta.fw_crc = 0xDEADBEEF;
    meta.image_sha256 = [0xAA; 32];
    meta.min_security_ver = 2;
    meta.gen = 7;

    store
        .write_fw_meta(BankSet::Vm1, Bank::A, &mut meta)
        .unwrap();
    let read = store.read_fw_meta(BankSet::Vm1, Bank::A).unwrap();

    assert_eq!(read.fw_seq, 10);
    assert_eq!(read.fw_secver, 3);
    assert_eq!(read.fw_crc, 0xDEADBEEF);
    assert_eq!(read.image_sha256, [0xAA; 32]);
    assert_eq!(read.min_security_ver, 2);
    assert_eq!(read.gen, 7);

    // Bank B should be empty
    assert!(store.read_fw_meta(BankSet::Vm1, Bank::B).is_none());
}

#[test]
fn runtime_roundtrip() {
    let mut store = make_store();
    let mut runtime = NvRuntime::default();
    runtime.did_count = 2;
    runtime.dids[0] = DidEntry {
        did: 0xFD10,
        len: 4,
        data: {
            let mut d = [0u8; 32];
            d[..4].copy_from_slice(b"test");
            d
        },
    };
    runtime.dids[1] = DidEntry {
        did: 0xFD11,
        len: 1,
        data: {
            let mut d = [0u8; 32];
            d[0] = 0xFF;
            d
        },
    };
    runtime.dtc_count = 1;
    runtime.dtcs[0] = DtcEntry {
        dtc_number: 0x00112233,
        status: 0x09,
    };

    store
        .write_runtime(BankSet::Vm2, Bank::B, &mut runtime)
        .unwrap();
    let read = store.read_runtime(BankSet::Vm2, Bank::B).unwrap();

    assert_eq!(read.did_count, 2);
    assert_eq!(read.dids[0].did, 0xFD10);
    assert_eq!(read.dids[0].len, 4);
    assert_eq!(&read.dids[0].data[..4], b"test");
    assert_eq!(read.dids[1].did, 0xFD11);
    assert_eq!(read.dids[1].data[0], 0xFF);
    assert_eq!(read.dtc_count, 1);
    assert_eq!(read.dtcs[0].dtc_number, 0x00112233);
    assert_eq!(read.dtcs[0].status, 0x09);
}

#[test]
fn app_roundtrip() {
    let mut store = make_store();
    let mut app = NvApp::default();
    app.data[0..4].copy_from_slice(&[1, 2, 3, 4]);
    app.data[2047] = 0xFF;

    store.write_app(&mut app).unwrap();
    let read = store.read_app().unwrap();

    assert_eq!(&read.data[0..4], &[1, 2, 3, 4]);
    assert_eq!(read.data[2047], 0xFF);
    assert_eq!(read.data[100], 0); // untouched bytes stay zero
}

#[test]
fn vehicle_state_roundtrip() {
    let mut store = make_store();
    let mut v = NvVehicle::default();
    v.vehicle_epoch = 7;

    store.write_vehicle_state(&mut v).unwrap();
    let read = store.read_vehicle_state().unwrap();

    assert_eq!(read.vehicle_epoch, 7);
}

#[test]
fn vehicle_epoch_bump_is_monotonic() {
    let mut store = make_store();
    // No record yet → first bump starts from default 0 → 1.
    assert_eq!(store.bump_vehicle_epoch().unwrap(), 1);
    assert_eq!(store.bump_vehicle_epoch().unwrap(), 2);
    assert_eq!(store.bump_vehicle_epoch().unwrap(), 3);
    // Persisted: a fresh read sees the latest, never an older value.
    assert_eq!(store.read_vehicle_state().unwrap().vehicle_epoch, 3);

    // A bump advances monotonically from a written value too.
    let mut v = NvVehicle::default();
    v.vehicle_epoch = 3;
    store.write_vehicle_state(&mut v).unwrap();
    assert_eq!(store.bump_vehicle_epoch().unwrap(), 4);
    assert_eq!(store.read_vehicle_state().unwrap().vehicle_epoch, 4);
}

#[test]
fn vehicle_region_isolated_from_app() {
    // The new region must not overlap App (or any other) — write both,
    // each survives the other.
    let mut store = make_store();
    let mut app = NvApp::default();
    app.data[0] = 0xAB;
    store.write_app(&mut app).unwrap();

    let mut v = NvVehicle::default();
    v.vehicle_epoch = 99;
    store.write_vehicle_state(&mut v).unwrap();

    assert_eq!(store.read_app().unwrap().data[0], 0xAB);
    assert_eq!(store.read_vehicle_state().unwrap().vehicle_epoch, 99);
}

#[test]
fn update_session_roundtrip() {
    let mut store = make_store();
    let mut s = NvUpdateSession::default();
    s.session_id = [0xAB; 32];
    s.reboot_owed = 0b101; // bank sets 0 and 2 owe the node reboot
    store.write_update_session(&mut s).unwrap();

    let read = store.read_update_session().unwrap();
    assert_eq!(read.session_id, [0xAB; 32]);
    assert_eq!(read.reboot_owed, 0b101);
    assert!(read.reboot_pending());
    assert!(read.owes(BankSet(0)) && read.owes(BankSet(2)));
    assert!(!read.owes(BankSet(1)));
}

#[test]
fn update_session_clear_drops_the_reboot_owed() {
    let mut store = make_store();
    let mut s = NvUpdateSession::default();
    s.session_id = [0x11; 32];
    s.reboot_owed = 0b1;
    store.write_update_session(&mut s).unwrap();
    assert!(store.read_update_session().unwrap().reboot_pending());

    store.clear_update_session().unwrap();
    let read = store.read_update_session().unwrap();
    assert!(!read.reboot_pending());
    assert_eq!(read.reboot_owed, 0);
}

#[test]
fn confirm_running_bank_match_clears_reboot_owed() {
    let mut store = make_store();
    // Os armed to B (finalize flipped the pointer), uncommitted, and owing a node reboot.
    let mut boot = NvBootState::default();
    boot.banks[BankSet::Os.as_index()].active_bank = Bank::B;
    boot.banks[BankSet::Os.as_index()].committed = false;
    store.write_boot_state(&mut boot).unwrap();
    let mut s = NvUpdateSession::default();
    s.reboot_owed = 1 << BankSet::Os.as_index();
    store.write_update_session(&mut s).unwrap();

    // Booted the armed bank (B) → the trial is live, the owed bit is cleared.
    let verdict = store.confirm_running_bank(BankSet::Os, Bank::B).unwrap();
    assert_eq!(verdict, RunningBankVerdict::Confirmed { bank: Bank::B });
    assert!(!store.read_update_session().unwrap().owes(BankSet::Os));
}

#[test]
fn confirm_running_bank_mismatch_leaves_reboot_owed() {
    let mut store = make_store();
    // Os armed to B, but the trial boot fell back to the recovery bank A.
    let mut boot = NvBootState::default();
    boot.banks[BankSet::Os.as_index()].active_bank = Bank::B;
    store.write_boot_state(&mut boot).unwrap();
    let mut s = NvUpdateSession::default();
    s.reboot_owed = 1 << BankSet::Os.as_index();
    store.write_update_session(&mut s).unwrap();

    let verdict = store.confirm_running_bank(BankSet::Os, Bank::A).unwrap();
    assert_eq!(
        verdict,
        RunningBankVerdict::Mismatch {
            running: Bank::A,
            armed: Bank::B,
        }
    );
    // The owed bit persists → phase stays RebootPending → the commit gate refuses.
    assert!(store.read_update_session().unwrap().owes(BankSet::Os));
}

#[test]
fn confirm_running_bank_without_boot_state_is_a_noop() {
    let mut store = make_store(); // no boot state written
    assert_eq!(
        store.confirm_running_bank(BankSet::Os, Bank::A).unwrap(),
        RunningBankVerdict::NoBootState
    );
}

#[test]
fn update_session_region_isolated() {
    // The new 0x8000 region must not overlap the vehicle / boot / app regions.
    let mut store = make_store();
    let mut v = NvVehicle::default();
    v.vehicle_epoch = 99;
    store.write_vehicle_state(&mut v).unwrap();

    let mut s = NvUpdateSession::default();
    s.reboot_owed = 0b10;
    store.write_update_session(&mut s).unwrap();

    assert_eq!(store.read_vehicle_state().unwrap().vehicle_epoch, 99);
    assert_eq!(store.read_update_session().unwrap().reboot_owed, 0b10);
}

// --- Sector rotation tests ---

#[test]
fn write_seq_increments() {
    let mut store = make_store();

    let mut state = NvBootState::default();
    store.write_boot_state(&mut state).unwrap();
    assert_eq!(state.write_seq, 1);

    state.banks[0].boot_count = 1;
    store.write_boot_state(&mut state).unwrap();
    assert_eq!(state.write_seq, 2);

    state.banks[0].boot_count = 2;
    store.write_boot_state(&mut state).unwrap();
    assert_eq!(state.write_seq, 3);

    // Read should return the latest
    let read = store.read_boot_state().unwrap();
    assert_eq!(read.write_seq, 3);
    assert_eq!(read.banks[0].boot_count, 2);
}

#[test]
fn sector_rotation_wraps_around() {
    let mut store = make_store();

    // Boot state has 2 sectors. Write 5 times — should wrap.
    for i in 0..5u8 {
        let mut state = NvBootState::default();
        state.banks[0].boot_count = i;
        store.write_boot_state(&mut state).unwrap();
    }

    let read = store.read_boot_state().unwrap();
    assert_eq!(read.write_seq, 5);
    assert_eq!(read.banks[0].boot_count, 4);
}

#[test]
fn fw_meta_rotation_with_4_sectors() {
    let mut store = make_store();

    // FW Meta has 4 sectors. Write 10 times.
    for i in 0..10u32 {
        let mut meta = NvFwMeta::default();
        meta.fw_seq = i;
        store
            .write_fw_meta(BankSet::Os, Bank::A, &mut meta)
            .unwrap();
    }

    let read = store.read_fw_meta(BankSet::Os, Bank::A).unwrap();
    assert_eq!(read.write_seq, 10);
    assert_eq!(read.fw_seq, 9);
}

// --- CRC corruption detection ---

#[test]
fn corrupted_sector_skipped() {
    let mut store = make_store();

    // Write a valid record
    let mut state = NvBootState::default();
    state.banks[0].boot_count = 42;
    store.write_boot_state(&mut state).unwrap();

    // Corrupt a byte in the first sector
    let mut dev = store.into_inner();
    // Corrupt byte 10 in sector 0
    let mut buf = [0u8; 1];
    dev.read(10, &mut buf).unwrap();
    let corrupted = buf[0] ^ 0xFF;
    dev.write(10, &[corrupted]).unwrap();

    let store = NvStore::new(dev);
    // With only 1 sector written and it's corrupted, read should return None
    assert!(store.read_boot_state().is_none());
}

#[test]
fn corrupted_sector_falls_back_to_older() {
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut store = NvStore::new(dev);

    // Write twice — fills sector 0 (seq=1) and sector 1 (seq=2)
    let mut state = NvBootState::default();
    state.banks[0].boot_count = 10;
    store.write_boot_state(&mut state).unwrap();

    state.banks[0].boot_count = 20;
    store.write_boot_state(&mut state).unwrap();

    // Corrupt sector 1 (the latest, at offset SECTOR_SIZE)
    let mut dev = store.into_inner();
    let mut buf = [0u8; 1];
    dev.read(SECTOR_SIZE as u64 + 10, &mut buf).unwrap();
    dev.write(SECTOR_SIZE as u64 + 10, &[buf[0] ^ 0xFF])
        .unwrap();

    let store = NvStore::new(dev);
    // Should fall back to sector 0 (seq=1, boot_count=10)
    let read = store.read_boot_state().unwrap();
    assert_eq!(read.write_seq, 1);
    assert_eq!(read.banks[0].boot_count, 10);
}

// --- Empty device ---

#[test]
fn empty_device_returns_none() {
    let store = make_store();
    assert!(store.read_boot_state().is_none());
    assert!(store.read_factory().is_none());
    assert!(store.read_app().is_none());
    assert!(store.read_fw_meta(BankSet::Vm1, Bank::A).is_none());
    assert!(store.read_runtime(BankSet::Vm1, Bank::A).is_none());
}

// --- Bank isolation ---

#[test]
fn bank_sets_are_isolated() {
    let mut store = make_store();

    // Write to VM1 Bank A. fw_seq distinguishes the records now that
    // the version string lives in the IVD manifest, not this blob.
    let mut meta1 = NvFwMeta::default();
    meta1.fw_seq = 10;
    store
        .write_fw_meta(BankSet::Vm1, Bank::A, &mut meta1)
        .unwrap();

    // Write to VM2 Bank A
    let mut meta2 = NvFwMeta::default();
    meta2.fw_seq = 20;
    store
        .write_fw_meta(BankSet::Vm2, Bank::A, &mut meta2)
        .unwrap();

    // Write to VM1 Bank B
    let mut meta3 = NvFwMeta::default();
    meta3.fw_seq = 11;
    store
        .write_fw_meta(BankSet::Vm1, Bank::B, &mut meta3)
        .unwrap();

    // Verify isolation
    let r1a = store.read_fw_meta(BankSet::Vm1, Bank::A).unwrap();
    let r2a = store.read_fw_meta(BankSet::Vm2, Bank::A).unwrap();
    let r1b = store.read_fw_meta(BankSet::Vm1, Bank::B).unwrap();

    assert_eq!(r1a.fw_seq, 10);
    assert_eq!(r2a.fw_seq, 20);
    assert_eq!(r1b.fw_seq, 11);

    // Hyp should be untouched
    assert!(store.read_fw_meta(BankSet::Os, Bank::A).is_none());
    assert!(store.read_fw_meta(BankSet::Os, Bank::B).is_none());
}

// --- Copy-on-update ---

#[test]
fn copy_runtime_clones_dids() {
    let mut store = make_store();

    // Write runtime to VM1 Bank A
    let mut runtime = NvRuntime::default();
    runtime.did_count = 1;
    runtime.dids[0] = DidEntry {
        did: 0xFD10,
        len: 3,
        data: {
            let mut d = [0u8; 32];
            d[..3].copy_from_slice(b"abc");
            d
        },
    };
    runtime.dtc_count = 1;
    runtime.dtcs[0] = DtcEntry {
        dtc_number: 0x001122,
        status: 0x01,
    };
    store
        .write_runtime(BankSet::Vm1, Bank::A, &mut runtime)
        .unwrap();

    // Copy A → B
    store.copy_runtime(BankSet::Vm1, Bank::A, Bank::B).unwrap();

    // Verify B has the same data
    let copied = store.read_runtime(BankSet::Vm1, Bank::B).unwrap();
    assert_eq!(copied.did_count, 1);
    assert_eq!(copied.dids[0].did, 0xFD10);
    assert_eq!(&copied.dids[0].data[..3], b"abc");
    assert_eq!(copied.dtc_count, 1);
    assert_eq!(copied.dtcs[0].dtc_number, 0x001122);

    // Modify A — B should be unaffected
    runtime.dids[0].data[0] = b'X';
    store
        .write_runtime(BankSet::Vm1, Bank::A, &mut runtime)
        .unwrap();

    let b_again = store.read_runtime(BankSet::Vm1, Bank::B).unwrap();
    assert_eq!(b_again.dids[0].data[0], b'a'); // still 'a', not 'X'
}

#[test]
fn copy_runtime_from_empty_writes_default() {
    let mut store = make_store();

    // Bank A has no runtime — copy should write empty default to Bank B
    store.copy_runtime(BankSet::Vm1, Bank::A, Bank::B).unwrap();

    let copied = store.read_runtime(BankSet::Vm1, Bank::B).unwrap();
    assert_eq!(copied.did_count, 0);
    assert_eq!(copied.dtc_count, 0);
}

// --- Boot state machine helpers ---

#[test]
fn trial_boot_increment() {
    let mut store = make_store();

    // Initial state: VM1 in trial mode
    let mut state = NvBootState::default();
    state.banks[1].committed = false;
    state.banks[1].boot_count = 0;
    store.write_boot_state(&mut state).unwrap();

    // Simulate 10 boots
    for expected_count in 1..=MAX_TRIAL_BOOTS {
        let mut s = store.read_boot_state().unwrap();
        s.banks[1].boot_count += 1;
        store.write_boot_state(&mut s).unwrap();

        let read = store.read_boot_state().unwrap();
        assert_eq!(read.banks[1].boot_count, expected_count);
        assert!(!read.banks[1].committed);
    }

    // After MAX_TRIAL_BOOTS, bootmgr would trigger rollback
    let s = store.read_boot_state().unwrap();
    assert_eq!(s.banks[1].boot_count, MAX_TRIAL_BOOTS);
}

#[test]
fn commit_clears_boot_count() {
    let mut store = make_store();

    let mut state = NvBootState::default();
    state.banks[0].active_bank = Bank::B;
    state.banks[0].committed = false;
    state.banks[0].boot_count = 5;
    store.write_boot_state(&mut state).unwrap();

    // Commit
    let mut s = store.read_boot_state().unwrap();
    s.banks[0].committed = true;
    s.banks[0].boot_count = 0;
    store.write_boot_state(&mut s).unwrap();

    let read = store.read_boot_state().unwrap();
    assert_eq!(read.banks[0].active_bank, Bank::B);
    assert!(read.banks[0].committed);
    assert_eq!(read.banks[0].boot_count, 0);
}

#[test]
fn rollback_swaps_bank() {
    let mut store = make_store();

    let mut state = NvBootState::default();
    state.banks[0].active_bank = Bank::B;
    state.banks[0].committed = false;
    state.banks[0].boot_count = 3;
    store.write_boot_state(&mut state).unwrap();

    // Rollback
    let mut s = store.read_boot_state().unwrap();
    s.banks[0].active_bank = s.banks[0].active_bank.other();
    s.banks[0].committed = true;
    s.banks[0].boot_count = 0;
    store.write_boot_state(&mut s).unwrap();

    let read = store.read_boot_state().unwrap();
    assert_eq!(read.banks[0].active_bank, Bank::A);
    assert!(read.banks[0].committed);
    assert_eq!(read.banks[0].boot_count, 0);
}

// --- Anti-rollback ---

#[test]
fn anti_rollback_floor_raised_on_commit() {
    let mut store = make_store();

    // Write FW Meta with secver=5, min_security_ver=2
    let mut meta = NvFwMeta::default();
    meta.fw_secver = 5;
    meta.min_security_ver = 2;
    store
        .write_fw_meta(BankSet::Vm1, Bank::A, &mut meta)
        .unwrap();

    // On commit: raise floor if secver > min
    let mut read = store.read_fw_meta(BankSet::Vm1, Bank::A).unwrap();
    if read.fw_secver > read.min_security_ver {
        read.min_security_ver = read.fw_secver;
    }
    store
        .write_fw_meta(BankSet::Vm1, Bank::A, &mut read)
        .unwrap();

    let final_read = store.read_fw_meta(BankSet::Vm1, Bank::A).unwrap();
    assert_eq!(final_read.min_security_ver, 5);
}

#[test]
fn anti_rollback_rejects_old_version() {
    let mut store = make_store();

    let mut meta = NvFwMeta::default();
    meta.min_security_ver = 5;
    store
        .write_fw_meta(BankSet::Vm1, Bank::A, &mut meta)
        .unwrap();

    let current = store.read_fw_meta(BankSet::Vm1, Bank::A).unwrap();

    // Simulate OTA with secver=3 — should be rejected
    let incoming_secver: u32 = 3;
    assert!(
        incoming_secver < current.min_security_ver,
        "should reject: incoming {} < floor {}",
        incoming_secver,
        current.min_security_ver
    );
}

// --- FileBlockDevice (integration, uses tempfile) ---

#[test]
fn file_block_device_roundtrip() {
    use crate::block::FileBlockDevice;

    let dir = std::env::temp_dir();
    let path = dir.join("nv-store-test.img");

    // Create and write
    {
        let dev = FileBlockDevice::create(&path, MIN_NV_DEVICE_SIZE).unwrap();
        let mut store = NvStore::new(dev);

        let mut state = NvBootState::default();
        state.banks[0].boot_count = 99;
        store.write_boot_state(&mut state).unwrap();
    }

    // Reopen and read
    {
        let dev = FileBlockDevice::open(&path).unwrap();
        let store = NvStore::new(dev);

        let read = store.read_boot_state().unwrap();
        assert_eq!(read.banks[0].boot_count, 99);
    }

    std::fs::remove_file(&path).ok();
}

#[test]
fn confirmed_running_trial_persists_boot_witness_before_clearing_reboot_owed() {
    let mut store = make_store();
    let mut state = NvBootState::default();
    let index = BankSet::Os.as_index();
    state.banks[index].active_bank = Bank::B;
    state.banks[index].committed = false;
    state.banks[index].boot_count = 0;
    store.write_boot_state(&mut state).unwrap();

    let mut session = NvUpdateSession {
        reboot_owed: 1 << index,
        ..Default::default()
    };
    store.write_update_session(&mut session).unwrap();

    assert_eq!(
        store.confirm_running_bank(BankSet::Os, Bank::B).unwrap(),
        RunningBankVerdict::Confirmed { bank: Bank::B }
    );
    assert_eq!(store.read_boot_state().unwrap().banks[index].boot_count, 1);
    assert_eq!(
        store.read_update_session().unwrap().reboot_owed & (1 << index),
        0
    );
}

#[test]
fn running_bank_mismatch_records_no_boot_witness() {
    let mut store = make_store();
    let mut state = NvBootState::default();
    let index = BankSet::Os.as_index();
    state.banks[index].active_bank = Bank::B;
    state.banks[index].committed = false;
    state.banks[index].boot_count = 0;
    store.write_boot_state(&mut state).unwrap();

    assert_eq!(
        store.confirm_running_bank(BankSet::Os, Bank::A).unwrap(),
        RunningBankVerdict::Mismatch {
            running: Bank::A,
            armed: Bank::B,
        }
    );
    assert_eq!(store.read_boot_state().unwrap().banks[index].boot_count, 0);
}

// --- Runtime slot count (derived from the device) ---

#[test]
fn nv_device_size_pins_the_layout() {
    // The sizes that exist in the field — a store created at one of these
    // must keep resolving to exactly that many slots.
    assert_eq!(nv_device_size(10), 0x100000); // the 2026-05-29 store
    assert_eq!(nv_device_size(16), 0x190000); // DEFAULT_SLOTS today
    assert_eq!(nv_device_size(32), 0x310000); // MAX_SLOTS
    assert_eq!(MIN_NV_DEVICE_SIZE, nv_device_size(DEFAULT_SLOTS));
}

#[test]
fn slot_count_comes_from_the_device_size() {
    let slots = |size: u64| NvStore::new(MemBlockDevice::new(size as usize)).slot_count();
    assert_eq!(slots(nv_device_size(10)), 10);
    assert_eq!(slots(nv_device_size(16)), 16);
    assert_eq!(slots(nv_device_size(32)), 32);
    // Space past MAX_SLOTS is simply not addressable — the mask and the
    // boot-state record stop there.
    assert_eq!(slots(0x400000), MAX_SLOTS);
    // One byte short of the first slot's full stride ⇒ no slots at all.
    assert_eq!(slots(layout::BANKSET_BASE + layout::BANKSET_STRIDE - 1), 0);
}

#[test]
fn slot_in_range_stops_at_the_count() {
    let store = NvStore::new(MemBlockDevice::new(nv_device_size(10) as usize));
    assert_eq!(store.slots().count(), 10);
    assert!(store.slot_in_range(BankSet(9)));
    assert!(!store.slot_in_range(BankSet(10)));
    // A slot the store can't address has no banks to read, and refuses writes.
    assert!(store.read_fw_meta(BankSet(10), Bank::A).is_none());
    assert!(store.read_runtime(BankSet(10), Bank::A).is_none());
}

#[test]
fn writes_to_an_unaddressable_slot_are_refused() {
    let mut store = NvStore::new(MemBlockDevice::new(nv_device_size(10) as usize));
    let mut meta = NvFwMeta::default();
    assert!(matches!(
        store.write_fw_meta(BankSet(10), Bank::A, &mut meta),
        Err(BlockError::OutOfBounds { .. })
    ));
    let mut runtime = NvRuntime::default();
    assert!(matches!(
        store.write_runtime(BankSet(10), Bank::A, &mut runtime),
        Err(BlockError::OutOfBounds { .. })
    ));
}

// --- Boot-state wire compatibility across the slot-count bumps ---

/// A boot sector byte-for-byte as the 10-slot writer produced it (in the field
/// 2026-05-29 … 2026-09-23): magic, seq, ten 3-byte entries, then the sector's
/// zero padding, CRC over everything before the last four bytes.
fn ten_slot_era_boot_sector(write_seq: u32) -> Vec<u8> {
    let mut sector = vec![0u8; SECTOR_SIZE];
    sector[0..4].copy_from_slice(&MAGIC_BOOT.to_le_bytes());
    sector[4..8].copy_from_slice(&write_seq.to_le_bytes());
    for i in 0..10 {
        let off = 8 + i * 3;
        sector[off] = (i % 2) as u8; // alternating Bank A / B
        sector[off + 1] = 1; // committed
        sector[off + 2] = i as u8; // boot_count
    }
    let crc = crc32fast::hash(&sector[..SECTOR_SIZE - 4]);
    sector[SECTOR_SIZE - 4..].copy_from_slice(&crc.to_le_bytes());
    sector
}

#[test]
fn ten_slot_era_boot_record_reads_through_a_bigger_store() {
    let mut dev = MemBlockDevice::new(nv_device_size(16) as usize);
    dev.write(layout::BOOT_OFFSET, &ten_slot_era_boot_sector(7))
        .unwrap();
    let store = NvStore::new(dev);

    let state = store.read_boot_state().expect("old record still decodes");
    assert_eq!(state.write_seq, 7);
    for i in 0..10 {
        let expect = if i % 2 == 0 { Bank::A } else { Bank::B };
        assert_eq!(state.banks[i].active_bank, expect, "slot {i}");
        assert!(state.banks[i].committed, "slot {i}");
        assert_eq!(state.banks[i].boot_count, i as u8, "slot {i}");
    }
    // Slots the old writer never wrote are the sector's zero padding, which
    // decodes as committed:FALSE (not the `default()` committed:true) — the
    // known downgrade-era shape. Harmless: those banks hold nothing, and only
    // an ARMED slot (active_bank flipped, boot_count > 0) is ever acted on.
    for i in 10..16 {
        assert_eq!(
            state.banks[i],
            BankBootState {
                active_bank: Bank::A,
                committed: false,
                boot_count: 0,
            },
            "slot {i}"
        );
    }
}

#[test]
fn slots_past_the_stores_count_read_back_as_default() {
    // The same record on a 10-slot store: everything from 10 up is forced to
    // the default, because this store cannot address those banks at all.
    let mut dev = MemBlockDevice::new(nv_device_size(10) as usize);
    dev.write(layout::BOOT_OFFSET, &ten_slot_era_boot_sector(7))
        .unwrap();
    let store = NvStore::new(dev);

    let state = store.read_boot_state().unwrap();
    assert_eq!(state.banks[9].boot_count, 9);
    for i in 10..MAX_SLOTS {
        assert_eq!(state.banks[i], BankBootState::default(), "slot {i}");
    }
}

#[test]
fn boot_state_round_trips_every_slot_on_a_full_store() {
    let mut store = NvStore::new(MemBlockDevice::new(nv_device_size(MAX_SLOTS) as usize));
    let mut state = NvBootState {
        write_seq: 0,
        banks: std::array::from_fn(|i| BankBootState {
            active_bank: if i % 3 == 0 { Bank::B } else { Bank::A },
            committed: i % 2 == 0,
            boot_count: i as u8,
        }),
    };
    store.write_boot_state(&mut state).unwrap();

    let read = store.read_boot_state().unwrap();
    for i in 0..MAX_SLOTS {
        assert_eq!(read.banks[i], state.banks[i], "slot {i}");
    }
}

// --- reboot_owed: u16 -> u32 (a pure extension, the field is last) ---

#[test]
fn u16_era_update_session_decodes_with_a_zero_upper_half() {
    let mut sector = vec![0u8; SECTOR_SIZE];
    sector[0..4].copy_from_slice(&MAGIC_UPDATE_SESSION.to_le_bytes());
    sector[4..8].copy_from_slice(&3u32.to_le_bytes());
    sector[8..40].copy_from_slice(&[0x5A; 32]);
    // The mask as the u16-era writer left it; [42..44] is sector padding.
    sector[40..42].copy_from_slice(&0b1_0000_0101u16.to_le_bytes());
    let crc = crc32fast::hash(&sector[..SECTOR_SIZE - 4]);
    sector[SECTOR_SIZE - 4..].copy_from_slice(&crc.to_le_bytes());

    let mut dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    dev.write(layout::UPDATE_SESSION_OFFSET, &sector).unwrap();
    let store = NvStore::new(dev);

    let s = store.read_update_session().expect("u16-era record decodes");
    assert_eq!(s.write_seq, 3);
    assert_eq!(s.session_id, [0x5A; 32]);
    assert_eq!(s.reboot_owed, 0b1_0000_0101);
    assert!(s.owes(BankSet(0)) && s.owes(BankSet(2)) && s.owes(BankSet(8)));
    assert!(!s.owes(BankSet(1)));
}

#[test]
fn reboot_owed_round_trips_the_top_slot() {
    let mut store = NvStore::new(MemBlockDevice::new(nv_device_size(MAX_SLOTS) as usize));
    let top = BankSet((MAX_SLOTS - 1) as u8);
    let mut s = NvUpdateSession {
        reboot_owed: 1u32 << top.as_index(),
        ..Default::default()
    };
    store.write_update_session(&mut s).unwrap();

    let read = store.read_update_session().unwrap();
    assert!(read.owes(top), "bit 31 survives the widened wire");
    assert!(!read.owes(BankSet(0)));
    assert!(read.reboot_pending());
}
