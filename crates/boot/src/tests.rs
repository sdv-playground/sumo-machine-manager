// Tests build NV records via `Default::default()` then mutate fields
// for readability — allow the lint module-wide.
#![allow(clippy::field_reassign_with_default)]

use nv_store::block::MemBlockDevice;
use nv_store::selector::{
    ComponentEntry, InMemorySelectorStore, SelectorBlob, SelectorStore, TestSigner,
};
use nv_store::slots;
use nv_store::store::{nv_device_size, MIN_NV_DEVICE_SIZE};
use nv_store::types::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::*;

fn make_bootmgr() -> BootManager<MemBlockDevice> {
    BootManager::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize))
}

// --- Slot count ---

#[test]
fn process_boot_returns_one_action_per_addressable_slot() {
    // The result is indexed by `BankSet::as_index()`, so its length has to
    // track the store's own slot count — not a compile-time constant.
    for slots in [10, 16] {
        let mut mgr = BootManager::new(MemBlockDevice::new(nv_device_size(slots) as usize));
        assert_eq!(mgr.nv().slot_count(), slots);
        assert_eq!(mgr.process_boot().unwrap().len(), slots, "first boot");
        assert_eq!(mgr.process_boot().unwrap().len(), slots, "steady state");
    }
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
    assert_eq!(
        actions[1],
        BootAction::TrialBoot {
            bank: Bank::B,
            boot_count: 1
        }
    );

    let actions = mgr.process_boot().unwrap();
    assert_eq!(
        actions[1],
        BootAction::TrialBoot {
            bank: Bank::B,
            boot_count: 2
        }
    );

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
        BootAction::TrialBoot {
            bank: Bank::B,
            boot_count: MAX_TRIAL_BOOTS
        }
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
        BootAction::AutoRollback {
            from: Bank::B,
            to: Bank::A
        }
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
        BootAction::AutoRollback {
            from: Bank::A,
            to: Bank::B
        }
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
            BootAction::TrialBoot {
                bank: Bank::B,
                boot_count: i
            }
        );
    }

    // 11th boot triggers auto-rollback
    let actions = mgr.process_boot().unwrap();
    assert_eq!(
        actions[0],
        BootAction::AutoRollback {
            from: Bank::B,
            to: Bank::A
        }
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
    assert_eq!(
        actions[1],
        BootAction::TrialBoot {
            bank: Bank::B,
            boot_count: 1
        }
    ); // vm1 trial
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
    assert_eq!(
        actions[0],
        BootAction::TrialBoot {
            bank: Bank::B,
            boot_count: 1
        }
    );
    assert_eq!(actions[1], BootAction::Boot { bank: Bank::A }); // VM1 committed
    assert_eq!(
        actions[2],
        BootAction::TrialBoot {
            bank: Bank::B,
            boot_count: 6
        }
    );
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
    mgr.nv_mut()
        .write_fw_meta(slots::VM1, Bank::A, &mut meta)
        .unwrap();

    let result = mgr.verify_image(slots::VM1, Bank::A, image_data);
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
    mgr.nv_mut()
        .write_fw_meta(slots::VM1, Bank::A, &mut meta)
        .unwrap();

    let result = mgr.verify_image(slots::VM1, Bank::A, image_data);
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

    let result = mgr.verify_image(slots::VM1, Bank::A, b"anything");
    assert_eq!(result, HashCheck::NoMeta);
}

#[test]
fn verify_image_zero_hash_is_no_meta() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    let mut meta = NvFwMeta::default(); // all zeros including hash
    mgr.nv_mut()
        .write_fw_meta(slots::VM1, Bank::A, &mut meta)
        .unwrap();

    let result = mgr.verify_image(slots::VM1, Bank::A, b"anything");
    assert_eq!(result, HashCheck::NoMeta);
}

// --- Hash failure handling ---

#[test]
fn hash_failure_in_trial_triggers_rollback() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    // Put VM1 in trial on Bank B
    let vm1 = slots::VM1.as_index();
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[vm1].active_bank = Bank::B;
    state.banks[vm1].committed = false;
    state.banks[vm1].boot_count = 3;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    let action = mgr.handle_hash_failure(slots::VM1).unwrap();
    assert_eq!(
        action,
        BootAction::HashRollback {
            from: Bank::B,
            to: Bank::A
        }
    );

    // Verify NV state
    let state = mgr.nv().read_boot_state().unwrap();
    assert_eq!(state.banks[vm1].active_bank, Bank::A);
    assert!(state.banks[vm1].committed);
    assert_eq!(state.banks[vm1].boot_count, 0);
}

#[test]
fn hash_failure_in_committed_is_fatal() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    let action = mgr.handle_hash_failure(slots::VM1).unwrap();
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

    assert_eq!(mgr.active_bank(slots::OS), Some(Bank::A));
    assert_eq!(mgr.active_bank(slots::VM1), Some(Bank::A));
    assert_eq!(mgr.active_bank(slots::VM2), Some(Bank::A));
}

#[test]
fn is_trial_query() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap();

    assert_eq!(mgr.is_trial(slots::VM1), Some(false));

    // Put into trial
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[slots::VM1.as_index()].committed = false;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    assert_eq!(mgr.is_trial(slots::VM1), Some(true));
}

// --- Simulated OTA + boot cycle ---

#[test]
fn ota_trial_commit_cycle() {
    let mut mgr = make_bootmgr();
    mgr.process_boot().unwrap(); // init

    // Simulate OTA: diagserver writes to inactive bank and updates boot state
    let image = b"new firmware image v2";
    let hash: [u8; 32] = Sha256::digest(image).into();

    // Write FW Meta for target bank. (Identity like fw_version lives in
    // the signed IVD manifest now; boot only reads image_sha256 + state.)
    let mut meta = NvFwMeta::default();
    meta.fw_secver = 2;
    meta.min_security_ver = 1;
    meta.image_sha256 = hash;
    mgr.nv_mut()
        .write_fw_meta(slots::VM1, Bank::B, &mut meta)
        .unwrap();

    // Switch to trial
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[1].active_bank = Bank::B;
    state.banks[1].committed = false;
    state.banks[1].boot_count = 0;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    // Boot 1: trial
    let actions = mgr.process_boot().unwrap();
    assert_eq!(
        actions[1],
        BootAction::TrialBoot {
            bank: Bank::B,
            boot_count: 1
        }
    );

    // Verify image
    assert_eq!(mgr.verify_image(slots::VM1, Bank::B, image), HashCheck::Ok);

    // Commit (simulating diagserver command)
    let mut state = mgr.nv().read_boot_state().unwrap();
    state.banks[1].committed = true;
    state.banks[1].boot_count = 0;
    mgr.nv_mut().write_boot_state(&mut state).unwrap();

    // Raise anti-rollback floor
    let mut meta = mgr.nv().read_fw_meta(slots::VM1, Bank::B).unwrap();
    if meta.fw_secver > meta.min_security_ver {
        meta.min_security_ver = meta.fw_secver;
    }
    mgr.nv_mut()
        .write_fw_meta(slots::VM1, Bank::B, &mut meta)
        .unwrap();

    // Next boot: committed on B
    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[1], BootAction::Boot { bank: Bank::B });

    // Verify anti-rollback floor was raised
    let meta = mgr.nv().read_fw_meta(slots::VM1, Bank::B).unwrap();
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
    assert_eq!(
        actions[1],
        BootAction::AutoRollback {
            from: Bank::B,
            to: Bank::A
        }
    );

    // Now committed on A
    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[1], BootAction::Boot { bank: Bank::A });
}

// ===========================================================================
// Boot-vector report
//
// PRIMARY = booted selection, SECONDARY = rollback floor, keyed by component
// id. A component is in trial iff its PRIMARY entry differs from its
// SECONDARY entry. The boot-vector path reports and writes nothing.
// ===========================================================================

/// Build a `BootManager` over an in-memory NV device with an attached
/// in-memory selector store. Returns both so the test can inspect/seed the
/// store directly.
fn make_bootmgr_with_selector() -> (BootManager<MemBlockDevice>, InMemorySelectorStore) {
    let store = InMemorySelectorStore::new();
    let mgr = BootManager::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize))
        .with_selector(Box::new(store.clone()));
    (mgr, store)
}

/// Build a signed boot vector (via `TestSigner`) for `entries` at `gen`.
fn signed_blob(gen: u64, entries: &[(&str, Bank)]) -> SelectorBlob {
    let entries = entries
        .iter()
        .map(|&(id, bank)| (id.to_string(), ComponentEntry::new(bank, BTreeMap::new())))
        .collect();
    SelectorBlob::signed(gen, entries, None, &TestSigner)
}

/// Seed PRIMARY == SECONDARY at the given selection — the committed baseline
/// (mirrors `seed_selector`'s seal+commit).
fn seed_committed(store: &InMemorySelectorStore, gen: u64, entries: &[(&str, Bank)]) {
    store.write_primary(&signed_blob(gen, entries)).unwrap();
    store.write_secondary(&signed_blob(gen, entries)).unwrap();
}

fn selected(component: &str, bank: Bank, trial: bool) -> BootAction {
    BootAction::Selected {
        component: component.to_string(),
        bank,
        trial,
    }
}

#[test]
fn selector_committed_boots_by_component_id() {
    let (mut mgr, store) = make_bootmgr_with_selector();
    // PRIMARY == SECONDARY: os=B, vm1=A — both committed.
    seed_committed(&store, 7, &[("vm1", Bank::A), ("os", Bank::B)]);

    let actions = mgr.process_boot().unwrap();
    assert_eq!(
        actions,
        [
            selected("os", Bank::B, false),
            selected("vm1", Bank::A, false)
        ],
        "one action per component, ascending id"
    );
}

#[test]
fn selector_path_writes_no_nv() {
    let (mut mgr, store) = make_bootmgr_with_selector();
    store
        .write_secondary(&signed_blob(1, &[("os", Bank::A)]))
        .unwrap();
    store
        .write_primary(&signed_blob(2, &[("os", Bank::B)]))
        .unwrap();

    for _ in 0..=MAX_TRIAL_BOOTS + 1 {
        let actions = mgr.process_boot().unwrap();
        assert_eq!(actions, [selected("os", Bank::B, true)]);
    }
    assert!(
        mgr.nv().read_boot_state().is_none(),
        "no trial counting, no rollback"
    );
    assert_eq!(store.read_primary().unwrap().generation, 2);
}

#[test]
fn selector_trial_and_committed_components_are_independent() {
    let (mut mgr, store) = make_bootmgr_with_selector();
    // os in trial (A floor, B booted); vm1 committed (A == A); vm2 sealed
    // after the floor (absent from SECONDARY) is in trial too.
    store
        .write_secondary(&signed_blob(1, &[("os", Bank::A), ("vm1", Bank::A)]))
        .unwrap();
    store
        .write_primary(&signed_blob(
            2,
            &[("os", Bank::B), ("vm1", Bank::A), ("vm2", Bank::B)],
        ))
        .unwrap();

    let actions = mgr.process_boot().unwrap();
    assert_eq!(
        actions,
        [
            selected("os", Bank::B, true),
            selected("vm1", Bank::A, false),
            selected("vm2", Bank::B, true),
        ]
    );
}

#[test]
fn selector_without_secondary_is_all_trial() {
    let (mut mgr, store) = make_bootmgr_with_selector();
    store
        .write_primary(&signed_blob(1, &[("os", Bank::A)]))
        .unwrap();

    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions, [selected("os", Bank::A, true)]);
}

#[test]
fn selector_absent_primary_falls_back_to_nv() {
    let (mut mgr, store) = make_bootmgr_with_selector();
    // Selector attached but NOT seeded — PRIMARY absent (first boot before
    // the host seeds it). Must behave exactly like the NV path.
    assert!(store.read_primary().is_none());

    let actions = mgr.process_boot().unwrap();
    // NV first-boot path: every set FirstBoot, NV initialized.
    for a in &actions {
        assert_eq!(*a, BootAction::FirstBoot);
    }
    let state = mgr.nv().read_boot_state().unwrap();
    for bs in &state.banks {
        assert_eq!(bs.active_bank, Bank::A);
        assert!(bs.committed);
    }

    // Second boot is committed on A — still NV (PRIMARY still absent), and the
    // selector store was never written by vm-boot.
    let actions = mgr.process_boot().unwrap();
    assert_eq!(actions[0], BootAction::Boot { bank: Bank::A });
    assert!(store.read_primary().is_none());

    // active_bank() is the NV bank.
    assert_eq!(mgr.active_bank(slots::OS), Some(Bank::A));
}
