// Tests construct records via `Default::default()` then mutate fields
// — the struct-init form would mean spelling out every default field
// at every call site for negligible benefit.  Allow at module scope.
#![allow(clippy::field_reassign_with_default)]

use crate::block::{BlockDevice, MemBlockDevice};
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
            .write_fw_meta(BankSet::HostOs, Bank::A, &mut meta)
            .unwrap();
    }

    let read = store.read_fw_meta(BankSet::HostOs, Bank::A).unwrap();
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
    assert!(store.read_fw_meta(BankSet::HostOs, Bank::A).is_none());
    assert!(store.read_fw_meta(BankSet::HostOs, Bank::B).is_none());
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
