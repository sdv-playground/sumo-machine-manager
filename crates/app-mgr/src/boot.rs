use std::sync::{Arc, Mutex};

use nv_store::block::BlockDevice;
use nv_store::store::NvStore;
use nv_store::types::{Bank, BankSet, MAX_TRIAL_BOOTS};

use crate::state::{self, AppConfig};

/// Boot-time self-check for the app component.
///
/// If in trial mode: increments boot_count, triggers auto-rollback if exceeded.
/// Returns the bank that the app should run from.
pub fn process_app_boot<D: BlockDevice>(config: &AppConfig, nv: &Arc<Mutex<NvStore<D>>>) -> Bank {
    let mut nv_guard = nv.lock().unwrap();

    let mut boot_state = match nv_guard.read_boot_state() {
        Some(s) => s,
        None => {
            tracing::info!("app: no boot state — first boot, using bank A");
            return Bank::A;
        }
    };

    let idx = BankSet::Os.as_index();
    let bs = &mut boot_state.banks[idx];

    if bs.committed {
        tracing::debug!(bank = ?bs.active_bank, "app: committed boot");
        return bs.active_bank;
    }

    // Trial mode — increment boot_count
    bs.boot_count += 1;
    tracing::info!(
        bank = ?bs.active_bank,
        boot_count = bs.boot_count,
        max = MAX_TRIAL_BOOTS,
        "app: trial boot"
    );

    if bs.boot_count > MAX_TRIAL_BOOTS {
        // Auto-rollback
        let failed_bank = bs.active_bank;
        bs.active_bank = failed_bank.other();
        bs.committed = true;
        bs.boot_count = 0;

        if let Err(e) = nv_guard.write_boot_state(&mut boot_state) {
            tracing::error!("app: failed to write rollback state: {e}");
            return failed_bank.other();
        }

        // Flip symlink back
        drop(nv_guard);
        if let Err(e) = state::flip_current_symlink(&config.base_path, failed_bank.other()) {
            tracing::error!("app: failed to flip symlink on rollback: {e}");
        }

        tracing::warn!(
            from = ?failed_bank,
            to = ?failed_bank.other(),
            "app: auto-rollback triggered (exceeded max trial boots)"
        );
        return failed_bank.other();
    }

    // Still in trial — persist incremented boot count
    let active = bs.active_bank;
    if let Err(e) = nv_guard.write_boot_state(&mut boot_state) {
        tracing::error!("app: failed to persist boot_count: {e}");
    }

    active
}
