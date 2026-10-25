//! Boot manager core logic — runs before launching the hypervisor or
//! guest VMs and reports, for each bank set or component, which bank boots.
//!
//! This crate is the **reference reader** of the boot-stage contract: it
//! shows how a boot stage reads the signed two-copy boot vector.
//!
//! On every boot:
//! 1. Read the boot selection (boot vector PRIMARY when a [`SelectorStore`]
//!    is attached and seeded, else NV Boot State)
//! 2. NV path only: for each bank set, handle trial mode (increment
//!    `boot_count`; auto-rollback once `boot_count > MAX_TRIAL_BOOTS`)
//! 3. Verify image hashes (SHA-256 recorded in FW Meta) against the
//!    real image bytes
//! 4. Return the `BootAction`s for the caller to execute
//!
//! # Boot authority: boot vector vs. NV
//!
//! Two authorities for "which bank boots":
//!
//! - **NV `NvBootState`** (the original): per-slot `active_bank` +
//!   `committed` + `boot_count`. Each slot commits/rolls back on its own.
//! - **Boot vector** (`nv_store::selector`): a single [`BootVector`],
//!   authenticated by the store, in a PRIMARY (booted) copy and a SECONDARY
//!   (rollback-floor) copy, keyed by component id. `bank =
//!   PRIMARY.entries[id].bank`; a component is in trial iff its PRIMARY entry
//!   differs from its SECONDARY entry (or SECONDARY has none).
//!
//! When a [`SelectorStore`] is attached (via [`BootManager::with_selector`])
//! **and** its PRIMARY slot exists, the boot vector is reported and NV is not
//! touched. Otherwise — no store, or PRIMARY absent (first boot: the host seeds
//! the boot vector only *after* `vm-boot` has run once) — the original NV path
//! runs unchanged.
//!
//! The boot vector carries no slot numbers, so the per-slot NV trial counter
//! cannot be tied to a component: on the boot-vector path this reader counts
//! no trial boots and performs no auto-rollback. The trial verdict (commit or
//! rollback) is the orchestrator's.
//!
//! Platform-independent — runs against any [`nv_store::block::BlockDevice`]
//! plus a byte slice for image verification. Actual VM launch is the
//! caller's job (QEMU on Linux dev, `qvm` on QNX).

use nv_store::block::BlockDevice;
use nv_store::selector::{BootVector, SelectorStore};
use nv_store::store::NvStore;
use nv_store::types::*;
use sha2::{Digest, Sha256};

/// Result of processing boot for a single bank set (NV path) or component
/// (boot-vector path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootAction {
    /// Boot-vector path: `component` boots `bank`; `trial` when its PRIMARY
    /// entry differs from its SECONDARY entry (or SECONDARY has none).
    Selected {
        component: String,
        bank: Bank,
        trial: bool,
    },
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
    /// Optional boot vector store. When attached **and** its PRIMARY slot
    /// exists, the boot vector is reported (see the module docs); otherwise
    /// the NV path runs. `None` = NV-only (the fallback).
    selector: Option<Box<dyn SelectorStore>>,
}

impl<D: BlockDevice> BootManager<D> {
    /// NV-only boot manager — the fallback. No selector attached, so
    /// `process_boot` / `active_bank` use `NvBootState` exclusively.
    pub fn new(dev: D) -> Self {
        Self {
            nv: NvStore::new(dev),
            selector: None,
        }
    }

    /// Attach a boot selector. Builder-style so call sites read
    /// `BootManager::new(dev).with_selector(Box::new(store))`. Once attached,
    /// `process_boot` reports the boot vector's PRIMARY slot (falling back to
    /// NV only while PRIMARY is absent — first boot).
    pub fn with_selector(mut self, selector: Box<dyn SelectorStore>) -> Self {
        self.selector = Some(selector);
        self
    }

    pub fn nv(&self) -> &NvStore<D> {
        &self.nv
    }

    pub fn nv_mut(&mut self) -> &mut NvStore<D> {
        &mut self.nv
    }

    /// Process boot. Does NOT verify image hashes — call `verify_image`
    /// separately for that.
    ///
    /// Boot-vector path, when a [`SelectorStore`] is attached *and* its
    /// PRIMARY slot exists: one [`BootAction::Selected`] per component in
    /// PRIMARY, in ascending id order; nothing is written.
    ///
    /// NV path otherwise (unchanged): handles trial mode and auto-rollback,
    /// writes updated boot state to NV, and returns one BootAction per bank
    /// set the store can address — the Vec's length is `nv().slot_count()`,
    /// indexed by `BankSet::as_index()`. An absent PRIMARY is first boot — the
    /// host seeds the boot vector only after `vm-boot` has run once — so it
    /// falls through to NV.
    pub fn process_boot(&mut self) -> Result<Vec<BootAction>, BootError> {
        if let Some(selector) = self.selector.as_ref() {
            if let Some(primary) = selector.read_primary() {
                let secondary = selector.read_secondary();
                return Ok(Self::process_boot_selector(&primary, secondary.as_ref()));
            }
            // PRIMARY absent — first boot before the selector is seeded. Fall
            // through to the NV path (unchanged) below.
        }
        self.process_boot_nv()
    }

    /// The original NV-driven boot: per-set `active_bank` / `committed` /
    /// `boot_count` in `NvBootState`, each set committing/rolling back on its
    /// own. Used when no selector is attached, or before PRIMARY is seeded.
    fn process_boot_nv(&mut self) -> Result<Vec<BootAction>, BootError> {
        let slots = self.nv.slot_count();
        let mut state = match self.nv.read_boot_state() {
            Some(s) => s,
            None => {
                // First boot — initialize default state (all committed to Bank A)
                let mut default = NvBootState::default();
                self.nv.write_boot_state(&mut default)?;
                return Ok(vec![BootAction::FirstBoot; slots]);
            }
        };

        let mut actions = vec![BootAction::FirstBoot; slots];
        let mut state_changed = false;

        for (i, bs) in state.banks.iter_mut().enumerate().take(slots) {
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

    /// Boot-vector report. The PRIMARY copy is the booted selection;
    /// SECONDARY is the rollback floor. For each component in PRIMARY
    /// (ascending id): its bank, and whether it is in trial — its SECONDARY
    /// entry is absent or differs.
    ///
    /// Writes nothing: the boot vector carries no slot, so there is no NV
    /// trial counter to advance for a component, and the trial verdict is the
    /// orchestrator's.
    fn process_boot_selector(
        primary: &BootVector,
        secondary: Option<&BootVector>,
    ) -> Vec<BootAction> {
        primary
            .entries
            .iter()
            .map(|(id, entry)| BootAction::Selected {
                component: id.clone(),
                bank: entry.bank,
                trial: secondary.and_then(|s| s.entries.get(id)) != Some(entry),
            })
            .collect()
    }

    /// Verify an image's SHA-256 hash against the expected hash in FW Meta.
    ///
    /// NOTE: the hash logic stays per-bank FW-meta and its rollback path
    /// ([`handle_hash_failure`](Self::handle_hash_failure)) is NV-side
    /// (`NvBootState`), independent of the boot vector.
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

    /// Get the NV active bank for a bank set. The boot vector is keyed by
    /// component id, not slot, so its banks are reported by
    /// [`process_boot`](Self::process_boot) instead.
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
