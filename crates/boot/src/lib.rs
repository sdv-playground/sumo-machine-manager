//! Boot manager core logic — runs before launching the hypervisor or
//! guest VMs and decides, for each bank set, whether to boot the active
//! bank, count a trial boot, or auto-rollback.
//!
//! On every boot:
//! 1. Read the boot selection (selector PRIMARY when a [`SelectorStore`]
//!    is attached, else NV Boot State)
//! 2. For each bank set, handle trial mode (increment `boot_count`;
//!    auto-rollback once `boot_count > MAX_TRIAL_BOOTS`)
//! 3. Verify image hashes (SHA-256 recorded in FW Meta) against the
//!    real image bytes
//! 4. Return one `BootAction` per bank set for the caller to execute
//!
//! # Boot authority: selector vs. NV
//!
//! Two authorities for "which bank does each set boot from":
//!
//! - **NV `NvBootState`** (the original): per-set `active_bank` +
//!   `committed` + `boot_count`. Each set commits/rolls back on its own.
//! - **Selector** (`nv_store::selector`): a single signed
//!   [`SelectorBlob`] in a PRIMARY (booted) slot and a SECONDARY
//!   (rollback-floor) slot. `bank = PRIMARY.selectors[set]`; a set is in
//!   trial iff `PRIMARY.selectors[set] != SECONDARY.selectors[set]`.
//!
//! When a [`SelectorStore`] is attached (via [`BootManager::with_selector`])
//! **and** its PRIMARY slot exists, the selector drives the bank decision.
//! Otherwise — no store, or PRIMARY absent (first boot: the host seeds the
//! selector only *after* `vm-boot` has run once) — the original NV path runs
//! unchanged.
//!
//! ## The trial / rollback is GLOBAL (whole-blob), not per-set
//!
//! `vm-boot` has no signer at boot, so the only selector write it can make is
//! copying the whole **already-signed** SECONDARY blob over PRIMARY
//! ([`SelectorStore::write_primary`]). A per-set rollback would change one
//! entry → require re-signing → impossible here. So when *any* trialed set
//! exceeds `MAX_TRIAL_BOOTS`, the rollback reverts **every** trialed set at
//! once (committed sets have `PRIMARY == SECONDARY`, so the copy is a no-op
//! for them). The per-set `boot_count` in `NvBootState` is reused purely as
//! the trial-boot counter — no NV layout change.
//!
//! Platform-independent — runs against any [`nv_store::block::BlockDevice`]
//! plus a byte slice for image verification. Actual VM launch is the
//! caller's job (QEMU on Linux dev, `qvm` on QNX).

use nv_store::block::BlockDevice;
use nv_store::selector::{SelectorBlob, SelectorStore};
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
    /// Optional boot selector. When attached **and** its PRIMARY slot exists,
    /// the selector drives the bank decision (see the module docs); otherwise
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
    /// `process_boot` consults the selector's PRIMARY slot for the bank
    /// decision (falling back to NV only while PRIMARY is absent — first boot).
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

    /// Process boot for all bank sets. Handles trial mode, auto-rollback,
    /// and writes updated boot state to NV.
    ///
    /// Returns one BootAction per bank set. Does NOT verify image hashes —
    /// call `verify_image` separately for that.
    ///
    /// Selector-driven when a [`SelectorStore`] is attached *and* its PRIMARY
    /// slot exists (see module docs); otherwise the NV path runs unchanged. An
    /// absent PRIMARY is first boot — the host seeds the selector only after
    /// `vm-boot` has run once — so it falls through to NV.
    pub fn process_boot(&mut self) -> Result<[BootAction; NUM_BANK_SETS], BootError> {
        if let Some(selector) = self.selector.as_ref() {
            if let Some(primary) = selector.read_primary() {
                let secondary = selector.read_secondary();
                return self.process_boot_selector(&primary, secondary.as_ref());
            }
            // PRIMARY absent — first boot before the selector is seeded. Fall
            // through to the NV path (unchanged) below.
        }
        self.process_boot_nv()
    }

    /// The original NV-driven boot: per-set `active_bank` / `committed` /
    /// `boot_count` in `NvBootState`, each set committing/rolling back on its
    /// own. Used when no selector is attached, or before PRIMARY is seeded.
    fn process_boot_nv(&mut self) -> Result<[BootAction; NUM_BANK_SETS], BootError> {
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

    /// Selector-driven boot. The signed PRIMARY blob is the booted selection;
    /// SECONDARY is the rollback floor. For each set the selector knows:
    ///
    /// - `bank = PRIMARY.selectors[set]`.
    /// - The set is **committed** iff `PRIMARY.selectors[set] ==
    ///   SECONDARY.selectors[set]` → emit [`BootAction::Boot`].
    /// - Otherwise the set is in **trial**: increment its NV `boot_count`
    ///   (reusing the per-set counter — no NV layout change) and emit
    ///   [`BootAction::TrialBoot`].
    ///
    /// If **any** trialed set's `boot_count` exceeds `MAX_TRIAL_BOOTS`, the
    /// whole node rolls back: the already-signed SECONDARY blob is copied
    /// verbatim over PRIMARY ([`SelectorStore::write_primary`]) — a GLOBAL
    /// revert (committed sets have `PRIMARY == SECONDARY`, so they no-op). Each
    /// reverted set gets its `boot_count` reset to 0 and an
    /// [`BootAction::AutoRollback`].
    ///
    /// Sets **absent** from the selector map fall back to their NV
    /// per-set logic — the selector is authoritative only for the sets it
    /// carries; NV remains authoritative for the rest (vm-boot drives both
    /// during the flip, set by set).
    fn process_boot_selector(
        &mut self,
        primary: &SelectorBlob,
        secondary: Option<&SelectorBlob>,
    ) -> Result<[BootAction; NUM_BANK_SETS], BootError> {
        // NV state still backs the per-set trial-boot counter (and any
        // not-in-selector sets). Initialize it on first sight, exactly like the
        // NV path, so `boot_count` storage exists.
        let mut state = match self.nv.read_boot_state() {
            Some(s) => s,
            None => {
                let mut default = NvBootState::default();
                self.nv.write_boot_state(&mut default)?;
                default
            }
        };

        let mut actions: [BootAction; NUM_BANK_SETS] =
            std::array::from_fn(|_| BootAction::FirstBoot);
        let mut state_changed = false;

        // First pass: classify each selector-known set and accumulate trial
        // boots. Defer the global-rollback decision until we know whether ANY
        // trialed set blew its budget.
        let mut any_trial_exceeded = false;
        // (index, primary_bank, secondary_bank) for each trialed set — used to
        // emit AutoRollback after a global revert.
        let mut trialed: Vec<(usize, Bank, Bank)> = Vec::new();
        let mut handled = [false; NUM_BANK_SETS];

        for (set, sel) in &primary.selectors {
            let bank = sel.bank;
            let idx = set.as_index();
            if idx >= NUM_BANK_SETS {
                continue;
            }
            handled[idx] = true;
            // Trial is a BANK-selection difference; the per-slot enable bit is
            // orthogonal (an idle disable must not look like a trial), so compare
            // the floor's bank only.
            let floor = secondary.and_then(|s| s.selectors.get(set).map(|s| s.bank));

            if floor == Some(bank) {
                // Committed: PRIMARY == SECONDARY for this set.
                actions[idx] = BootAction::Boot { bank };
            } else {
                // Trial: PRIMARY diverges from the floor. Count the boot.
                let bs = &mut state.banks[idx];
                bs.boot_count += 1;
                state_changed = true;
                if bs.boot_count > MAX_TRIAL_BOOTS {
                    any_trial_exceeded = true;
                }
                // `floor` is the bank we'd revert to. If SECONDARY is absent
                // (or lacks this set) there is no floor to roll back to; the
                // set stays in trial regardless of count.
                if let Some(to) = floor {
                    trialed.push((idx, bank, to));
                } else {
                    actions[idx] = BootAction::TrialBoot {
                        bank,
                        boot_count: bs.boot_count,
                    };
                }
            }
        }

        // Second pass: a single trialed set over budget rolls back the WHOLE
        // signed blob (we cannot re-sign a per-set change at boot). Only
        // possible when SECONDARY exists — that is the blob we copy over
        // PRIMARY. Without it there is nothing signed to revert to, so we leave
        // the sets in trial.
        let do_global_rollback = any_trial_exceeded && secondary.is_some();
        if do_global_rollback {
            let secondary = secondary.expect("checked is_some");
            // Copy the already-signed SECONDARY over PRIMARY — the only write
            // vm-boot can make without a signer.
            self.selector
                .as_ref()
                .expect("selector present in this path")
                .write_primary(secondary);
            for &(idx, from, to) in &trialed {
                state.banks[idx].boot_count = 0;
                actions[idx] = BootAction::AutoRollback { from, to };
            }
        } else {
            // No rollback: every trialed-with-floor set just keeps trialing.
            for &(idx, bank, _to) in &trialed {
                actions[idx] = BootAction::TrialBoot {
                    bank,
                    boot_count: state.banks[idx].boot_count,
                };
            }
        }

        // Sets the selector doesn't carry fall back to their NV per-set logic
        // (committed → Boot; trial → count / NV-rollback). Keeps NV authority
        // intact for components not yet flipped onto the selector.
        for i in 0..NUM_BANK_SETS {
            if handled[i] {
                continue;
            }
            let bs = &mut state.banks[i];
            if bs.committed {
                actions[i] = BootAction::Boot {
                    bank: bs.active_bank,
                };
            } else {
                bs.boot_count += 1;
                state_changed = true;
                if bs.boot_count > MAX_TRIAL_BOOTS {
                    let old_bank = bs.active_bank;
                    bs.active_bank = bs.active_bank.other();
                    bs.committed = true;
                    bs.boot_count = 0;
                    actions[i] = BootAction::AutoRollback {
                        from: old_bank,
                        to: bs.active_bank,
                    };
                } else {
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
    ///
    /// NOTE: the hash logic stays per-bank FW-meta and its rollback path
    /// ([`handle_hash_failure`](Self::handle_hash_failure)) is still NV-side
    /// (`NvBootState`), independent of the selector. Aligning hash-driven
    /// rollback with the selector's whole-blob revert is a later step; this
    /// sub-step only moves the trial-counting bank decision onto the selector.
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
    ///
    /// Selector-resolved (`PRIMARY.selectors[set]`) when a [`SelectorStore`] is
    /// attached and its PRIMARY slot carries this set; otherwise the NV
    /// `active_bank`. (A selector whose PRIMARY lacks this set still falls back
    /// to NV — a set may be selector-driven while another is still NV-driven
    /// during the flip.)
    pub fn active_bank(&self, set: BankSet) -> Option<Bank> {
        if let Some(selector) = self.selector.as_ref() {
            if let Some(primary) = selector.read_primary() {
                if let Some(sel) = primary.selectors.get(&set) {
                    return Some(sel.bank);
                }
            }
        }
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
