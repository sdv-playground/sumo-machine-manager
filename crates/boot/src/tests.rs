use nv_store::block::MemBlockDevice;
use nv_store::store::MIN_NV_DEVICE_SIZE;
use nv_store::types::*;
use sha2::{Sha256, Digest};

use crate::*;

fn make_bootmgr() -> BootManager<MemBlockDevice> {
    BootManager::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize))
}

// --- First boot ---

#[test]
fn first_boot_initializes_state() {
    let mut mgr = make_bootmgr();
    let actions = mgr.process_boot().unwrap();

    assert_eq!(actions[0], BootAction::FirstBoot);
    assert_eq!(actions[1], BootAction::FirstBoot);
    assert_eq!(actions[2], BootAction::FirstBoot);

    // NV state should now be initialized
    let state = mgr.nv().read_boot_state().unwrap();
    for bs in &state.banks {
        assert_eq!(bs.active_bank, Bank::A);
        assert!(bs.committed);
        assert_eq!(bs.boot_count, 0);
    }
}

#[test]
fn second_boot_after_first_is_committed() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap(); // first boot

    let actions = mgr.process_boot().unwrap();
    for action in &actions {
        assert_eq!(*action, BootAction::Boot { bank: Bank::A });
    }
}

// --- Committed boot ---

#[test]
fn committed_boot_does_not_increment_count() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap(); // init

    // Boot 5 times in committed mode
    for _ in 0..5 {
        let actions = mgr.process_boot().unwrap();
        assert_eq!(actions[0], BootAction::Boot { bank: Bank::A });
    }

    let state = mgr.nv().read_boot_state().unwrap();
    assert_eq!(state.banks[0].boot_count, 0); // unchanged
}

// --- Trial boot ---

#[test]
fn trial_boot_increments_count() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap(); // init

    // Put VM1 into trial mode on Bank B
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[1].active_bank = Bank::B;
    state.banks[1].committed = false;
    state.banks[1].boot_count = 0;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[1], BootAction::TrialBoot { bank: Bank::B, boot_count: 1 });

    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[1], BootAction::TrialBoot { bank: Bank::B, boot_count: 2 });

    // Hyp and VM2 should still be committed
    assert_eq!(actions[0], BootAction::Boot { bank: Bank::A });
    assert_eq!(actions[2], BootAction::Boot { bank: Bank::A });
}

#[test]
fn trial_boot_at_max_still_boots() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[0].active_bank = Bank::B;
    state.banks[0].committed = false;
    state.banks[0].boot_count = MAX_TRIAL_BOOTS - 1; // one boot left
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    let actions = mgr.process_boot().unwrap();
    assert_eq!(
        actions[0],
        BootAction::TrialBoot { bank: Bank::B, boot_count: MAX_TRIAL_BOOTS }
    );
}

// --- Auto-rollback ---

#[test]
fn auto_rollback_after_max_trial_boots() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    // Set VM1 to trial with count at MAX (next boot triggers rollback)
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[1].active_bank = Bank::B;
    state.banks[1].committed = false;
    state.banks[1].boot_count = MAX_TRIAL_BOOTS;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    let actions = mgr.process_boot().unwrap();
    assert_eq!(
        actions[1],
        BootAction::AutoRollback { from: Bank::B, to: Bank::A }
    );

    // Verify NV state: rolled back to A, committed
    let state = mgr.nv().read_boot_state().unwrap();
    assert_eq!(state.banks[1].active_bank, Bank::A);
    assert!(state.banks[1].committed);
    assert_eq!(state.banks[1].boot_count, 0);
}

#[test]
fn auto_rollback_from_a_to_b() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[0].active_bank = Bank::A;
    state.banks[0].committed = false;
    state.banks[0].boot_count = MAX_TRIAL_BOOTS;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    let actions = mgr.process_boot().unwrap();
    assert_eq!(
        actions[0],
        BootAction::AutoRollback { from: Bank::A, to: Bank::B }
    );
}

#[test]
fn full_trial_cycle_10_boots_then_rollback() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    // Start trial on Bank B
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[0].active_bank = Bank::B;
    state.banks[0].committed = false;
    state.banks[0].boot_count = 0;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    // 10 trial boots
    for i in 1..=MAX_TRIAL_BOOTS {
        let actions = mgr.process_boot().unwrap();
        assert_eq!(
            actions[0],
            BootAction::TrialBoot { bank: Bank::B, boot_count: i }
        );
    }

    // 11th boot triggers auto-rollback
    let actions = mgr.process_boot().unwrap();
    assert_eq!(
        actions[0],
        BootAction::AutoRollback { from: Bank::B, to: Bank::A }
    );

    // Subsequent boots are committed on A
    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[0], BootAction::Boot { bank: Bank::A });
}

// --- Bank set independence ---

#[test]
fn bank_sets_independent_trial() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    // VM1 in trial, Hyp and VM2 committed
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[1].active_bank = Bank::B;
    state.banks[1].committed = false;
    state.banks[1].boot_count = 0;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[0], BootAction::Boot { bank: Bank::A }); // hyp committed
    assert_eq!(actions[1], BootAction::TrialBoot { bank: Bank::B, boot_count: 1 }); // vm1 trial
    assert_eq!(actions[2], BootAction::Boot { bank: Bank::A }); // vm2 committed
}

#[test]
fn multiple_bank_sets_in_trial() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    let mut state = mgr.nv().read_boot_state().unwrap();
    // Hyp on trial (bank B), VM2 on trial (bank B)
    state.banks[0].active_bank = Bank::B;
    state.banks[0].committed = false;
    state.banks[0].boot_count = 0;
    state.banks[2].active_bank = Bank::B;
    state.banks[2].committed = false;
    state.banks[2].boot_count = 5;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[0], BootAction::TrialBoot { bank: Bank::B, boot_count: 1 });
    assert_eq!(actions[1], BootAction::Boot { bank: Bank::A }); // VM1 committed
    assert_eq!(actions[2], BootAction::TrialBoot { bank: Bank::B, boot_count: 6 });
}

// --- Hash verification ---

#[test]
fn verify_image_correct_hash() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    let image_data = b"this is a test firmware image";
    let expected_hash: [u8; 32] = Sha256::digest(image_data).into();

    let mut meta = NvFwMeta::default();
    meta.image_sha256 = expected_hash;
    mgr.nv_mut().write_fw_meta(BankSet::Vm1, Bank::A, &mut meta).unwrap();

    let result = mgr.verify_image(BankSet::Vm1, Bank::A, image_data);
    assert_eq!(result, HashCheck::Ok);
}

#[test]
fn verify_image_wrong_hash() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    let image_data = b"this is a test firmware image";
    let wrong_data = b"this is a DIFFERENT firmware image";

    let mut meta = NvFwMeta::default();
    meta.image_sha256 = Sha256::digest(wrong_data).into();
    mgr.nv_mut().write_fw_meta(BankSet::Vm1, Bank::A, &mut meta).unwrap();

    let result = mgr.verify_image(BankSet::Vm1, Bank::A, image_data);
    match result {
        HashCheck::Mismatch { expected, actual } => {
            assert_eq!(expected, Sha256::digest(wrong_data).as_slice());
            assert_eq!(actual, Sha256::digest(image_data).as_slice());
        }
        other => panic!("expected Mismatch, got {other:?}"),
    }
}

#[test]
fn verify_image_no_meta() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    let result = mgr.verify_image(BankSet::Vm1, Bank::A, b"anything");
    assert_eq!(result, HashCheck::NoMeta);
}

#[test]
fn verify_image_zero_hash_is_no_meta() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    let mut meta = NvFwMeta::default(); // all zeros including hash
    mgr.nv_mut().write_fw_meta(BankSet::Vm1, Bank::A, &mut meta).unwrap();

    let result = mgr.verify_image(BankSet::Vm1, Bank::A, b"anything");
    assert_eq!(result, HashCheck::NoMeta);
}

// --- Hash failure handling ---

#[test]
fn hash_failure_in_trial_triggers_rollback() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    // Put VM1 in trial on Bank B
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[1].active_bank = Bank::B;
    state.banks[1].committed = false;
    state.banks[1].boot_count = 3;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    let action = mgr.handle_hash_failure(BankSet::Vm1).unwrap();
    assert_eq!(action, BootAction::HashRollback { from: Bank::B, to: Bank::A });

    // Verify NV state
    let state = mgr.nv().read_boot_state().unwrap();
    assert_eq!(state.banks[1].active_bank, Bank::A);
    assert!(state.banks[1].committed);
    assert_eq!(state.banks[1].boot_count, 0);
}

#[test]
fn hash_failure_in_committed_is_fatal() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    let action = mgr.handle_hash_failure(BankSet::Vm1).unwrap();
    assert_eq!(action, BootAction::HashFatal { bank: Bank::A });

    // NV state unchanged — committed image is corrupt, nothing to do
    let state = mgr.nv().read_boot_state().unwrap();
    assert!(state.banks[1].committed);
}

// --- Helper methods ---

#[test]
fn active_bank_query() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    assert_eq!(mgr.active_bank(BankSet::HostOs), Some(Bank::A));
    assert_eq!(mgr.active_bank(BankSet::Vm1), Some(Bank::A));
    assert_eq!(mgr.active_bank(BankSet::Vm2), Some(Bank::A));
}

#[test]
fn is_trial_query() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    assert_eq!(mgr.is_trial(BankSet::Vm1), Some(false));

    // Put into trial
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[1].committed = false;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    assert_eq!(mgr.is_trial(BankSet::Vm1), Some(true));
}

// --- Simulated OTA + boot cycle ---

#[test]
fn ota_trial_commit_cycle() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap(); // init

    // Simulate OTA: diagserver writes to inactive bank and updates boot state
    let image = b"new firmware image v2";
    let hash: [u8; 32] = Sha256::digest(image).into();

    // Write FW Meta for target bank
    let mut meta = NvFwMeta::default();
    meta.fw_version[..2].copy_from_slice(b"v2");
    meta.fw_secver = 2;
    meta.min_security_ver = 1;
    meta.image_sha256 = hash;
    mgr.nv_mut().write_fw_meta(BankSet::Vm1, Bank::B, &mut meta).unwrap();

    // Switch to trial
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[1].active_bank = Bank::B;
    state.banks[1].committed = false;
    state.banks[1].boot_count = 0;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    // Boot 1: trial
    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[1], BootAction::TrialBoot { bank: Bank::B, boot_count: 1 });

    // Verify image
    assert_eq!(mgr.verify_image(BankSet::Vm1, Bank::B, image), HashCheck::Ok);

    // Commit (simulating diagserver command)
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[1].committed = true;
    state.banks[1].boot_count = 0;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    // Raise anti-rollback floor
    let mut meta = mgr.nv().read_fw_meta(BankSet::Vm1, Bank::B).unwrap();
    if meta.fw_secver > meta.min_security_ver {
        meta.min_security_ver = meta.fw_secver;
    }
    mgr.nv_mut().write_fw_meta(BankSet::Vm1, Bank::B, &mut meta).unwrap();

    // Next boot: committed on B
    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[1], BootAction::Boot { bank: Bank::B });

    // Verify anti-rollback floor was raised
    let meta = mgr.nv().read_fw_meta(BankSet::Vm1, Bank::B).unwrap();
    assert_eq!(meta.min_security_ver, 2);
}

#[test]
fn ota_trial_auto_rollback_cycle() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    // OTA: switch VM1 to Bank B, trial mode
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[1].active_bank = Bank::B;
    state.banks[1].committed = false;
    state.banks[1].boot_count = 0;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    // Boot 10 times without committing
    for _ in 0..MAX_TRIAL_BOOTS {
        let actions = mgr.process_boot().unwrap();
        match actions[1] {
            BootAction::TrialBoot { bank: Bank::B, .. } => {}
            _ => panic!("expected trial boot on B"),
        }
    }

    // 11th boot: auto-rollback
    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[1], BootAction::AutoRollback { from: Bank::B, to: Bank::A });

    // Now committed on A
    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[1], BootAction::Boot { bank: Bank::A });
}
