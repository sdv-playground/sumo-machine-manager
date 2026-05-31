//! Boot manager core logic — runs before launching the hypervisor or
//! guest VMs and decides, for each bank set, whether to boot the active
//! bank, count a trial boot, or auto-rollback.
//!
//! On every boot:
//! 1. Read NV Boot State
//! 2. For each bank set, handle trial mode (increment `boot_count`;
//!    auto-rollback once `boot_count > MAX_TRIAL_BOOTS`)
//! 3. Verify image hashes (SHA-256 recorded in FW Meta) against the
//!    real image bytes
//! 4. Return one `BootAction` per bank set for the caller to execute
//!
//! Platform-independent — runs against any [`nv_store::block::BlockDevice`]
//! plus a byte slice for image verification. Actual VM launch is the
//! caller's job (QEMU on Linux dev, `qvm` on QNX).

use nv_store::block::BlockDevice;
use nv_store::store::NvStore;
use nv_store::types::*;
use sha2::{Digest, Sha256};

/// Result of processing boot for a single bank set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootAction {
    /// Normal boot from committed bank.
    Boot { bank: Bank },
    /// Trial boot — bank was updated but not yet committed.
    TrialBoot { bank: Bank, boot_count: u8 },
    /// Auto-rollback triggered (exceeded MAX_TRIAL_BOOTS).
    AutoRollback { from: Bank, to: Bank },
    /// Image hash verification failed in trial mode — immediate rollback.
    HashRollback { from: Bank, to: Bank },
    /// Image hash verification failed in committed mode — fatal.
    HashFatal { bank: Bank },
    /// No boot state initialized yet — first boot.
    FirstBoot,
}

/// Result of hash verification for a single bank set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashCheck {
    /// Hash matches expected value.
    Ok,
    /// Hash mismatch.
    Mismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// No FW meta found — no expected hash to verify against.
    NoMeta,
}

#[derive(Debug)]
pub enum BootError {
    Nv(nv_store::block::BlockError),
}

impl From<nv_store::block::BlockError> for BootError {
    fn from(e: nv_store::block::BlockError) -> Self {
        BootError::Nv(e)
    }
}

impl std::fmt::Display for BootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootError::Nv(e) => write!(f, "NV store error: {e}"),
        }
    }
}

pub struct BootManager<D: BlockDevice> {
    nv: NvStore<D>,
}

impl<D: BlockDevice> BootManager<D> {
    pub fn new(dev: D) -> Self {
        Self {
            nv: NvStore::new(dev),
        }
    }

    pub fn nv(&self) -> &NvStore<D> {
        &self.nv
    }

    pub fn nv_mut(&mut self) -> &mut NvStore<D> {
        &mut self.nv
    }

    /// Process boot for all bank sets. Handles trial mode, auto-rollback,
    /// and writes updated boot state to NV.
    ///
    /// Returns one BootAction per bank set. Does NOT verify image hashes —
    /// call `verify_image` separately for that.
    pub fn process_boot(&mut self) -> Result<[BootAction; NUM_BANK_SETS], BootError> {
        let mut state = match self.nv.read_boot_state() {
            Some(s) => s,
            None => {
                // First boot — initialize default state (all committed to Bank A)
                let mut default = NvBootState::default();
                self.nv.write_boot_state(&mut default)?;
                return Ok(std::array::from_fn(|_| BootAction::FirstBoot));
            }
        };

        let mut actions: [BootAction; NUM_BANK_SETS] =
            std::array::from_fn(|_| BootAction::FirstBoot);
        let mut state_changed = false;

        for (i, bs) in state.banks.iter_mut().enumerate() {
            if bs.committed {
                actions[i] = BootAction::Boot {
                    bank: bs.active_bank,
                };
            } else {
                // Trial mode
                bs.boot_count += 1;

                if bs.boot_count > MAX_TRIAL_BOOTS {
                    // Auto-rollback
                    let old_bank = bs.active_bank;
                    bs.active_bank = bs.active_bank.other();
                    bs.committed = true;
                    bs.boot_count = 0;
                    state_changed = true;
                    actions[i] = BootAction::AutoRollback {
                        from: old_bank,
                        to: bs.active_bank,
                    };
                } else {
                    state_changed = true;
                    actions[i] = BootAction::TrialBoot {
                        bank: bs.active_bank,
                        boot_count: bs.boot_count,
                    };
                }
            }
        }

        if state_changed {
            self.nv.write_boot_state(&mut state)?;
        }

        Ok(actions)
    }

    /// Verify an image's SHA-256 hash against the expected hash in FW Meta.
    pub fn verify_image(&self, set: BankSet, bank: Bank, image_data: &[u8]) -> HashCheck {
        let meta = match self.nv.read_fw_meta(set, bank) {
            Some(m) => m,
            None => return HashCheck::NoMeta,
        };

        // All-zero hash means "no hash stored" — skip verification
        if meta.image_sha256 == [0u8; 32] {
            return HashCheck::NoMeta;
        }

        let mut hasher = Sha256::new();
        hasher.update(image_data);
        let actual: [u8; 32] = hasher.finalize().into();

        if actual == meta.image_sha256 {
            HashCheck::Ok
        } else {
            HashCheck::Mismatch {
                expected: meta.image_sha256,
                actual,
            }
        }
    }

    /// Handle hash verification failure — rollback if trial, fatal if committed.
    pub fn handle_hash_failure(&mut self, set: BankSet) -> Result<BootAction, BootError> {
        let mut state = match self.nv.read_boot_state() {
            Some(s) => s,
            None => return Ok(BootAction::FirstBoot),
        };

        let idx = set.as_index();

        if state.banks[idx].committed {
            Ok(BootAction::HashFatal {
                bank: state.banks[idx].active_bank,
            })
        } else {
            let from = state.banks[idx].active_bank;
            let to = from.other();
            state.banks[idx].active_bank = to;
            state.banks[idx].committed = true;
            state.banks[idx].boot_count = 0;
            self.nv.write_boot_state(&mut state)?;
            Ok(BootAction::HashRollback { from, to })
        }
    }

    /// Get the current active bank for a bank set.
    pub fn active_bank(&self, set: BankSet) -> Option<Bank> {
        self.nv
            .read_boot_state()
            .map(|s| s.banks[set.as_index()].active_bank)
    }

    /// Check if a bank set is in trial mode.
    pub fn is_trial(&self, set: BankSet) -> Option<bool> {
        self.nv
            .read_boot_state()
            .map(|s| !s.banks[set.as_index()].committed)
    }
}

#[cfg(test)]
mod tests;
