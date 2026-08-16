//! SystemBankState — the node's single signed, generation-counted boot
//! selector.
//!
//! This is `nv_store::NvBootState` *grown up*. Where `NvBootState` records a
//! per-bank-set `(active_bank, committed, boot_count)` triple with no global
//! ordering and no attestation, `SystemBankState` is the **one** answer to
//! "which bank does each component boot from", carrying:
//!
//! - a **global generation** counter (anti-rollback across the whole node, not
//!   per-bank-set), monotonic on `seal`;
//! - an **HSM signature** over the selector contents (anti-forge — a bootloader
//!   verifies before honouring the selector);
//! - an explicit **PRIMARY / SECONDARY** split:
//!   - `PRIMARY`  = the **booted** selector (`current`);
//!   - `SECONDARY` = the **rollback floor** (`committed`) — the selector the
//!     node falls back to if a trial fails.
//!
//! It is written atomically at exactly **one** point — [`SystemBankManager::seal`]
//! — and is intentionally **separate** from each component's per-bank IVD
//! manifest. `BankProvider::read_installed` (the signed CBOR manifest in a bank
//! dir) stays untouched: that answers "what firmware *is* installed in bank X",
//! this answers "which bank does the node *boot*".
//!
//! # Layering
//!
//! The selector STORAGE primitives — the on-medium [`SelectorBlob`], the
//! two-slot persistence seam ([`SelectorStore`] + stub / in-memory / file
//! impls) and the attestation seam ([`Signer`] + stub / test impls) — now live
//! one crate down in [`nv_store::selector`], so a lower crate (e.g. `vm-boot`)
//! can read the selector without depending **up** on `machine-mgr`. They are
//! re-exported here so the `machine_mgr::system_bank_state::*` import surface is
//! unchanged. The transition engine ([`SystemBankManager`]) and the read-only
//! [`BootSelector`] view stay here.
//!
//! # Status: additive shadow, not yet load-bearing
//!
//! The physical sector layout for the selector partition is a **bootloader
//! contract that does not exist yet**. So the production [`SelectorStore`] and
//! [`Signer`] are loud stubs ([`StubSelectorStore`] / [`StubSigner`]) that
//! warn and no-op. The cache + state transitions are fully real and unit-tested
//! against in-memory seams (`InMemorySelectorStore` / `TestSigner`, gated
//! behind the `test-seams` feature so production builds never link them) so the
//! state machine is correct the day the sector contract lands — at which point
//! the stubs are swapped for real eMMC sector I/O + HSM signing and this becomes
//! the authority. Until then the existing per-component commit/rollback
//! (`BankProvider` + `NvBootState`) remains the authority; this runs alongside.

use std::collections::{BTreeMap, BTreeSet};

use nv_store::types::{Bank, BankSet};

// The selector STORAGE primitives moved down into `nv-store` so a lower crate
// can read the selector without depending up on `machine-mgr`. Re-exported here
// so existing `machine_mgr::system_bank_state::*` paths still resolve.
pub use nv_store::selector::{
    FileSelectorStore, SelectorBlob, SelectorStore, Signer, StubSelectorStore, StubSigner,
};
// In-memory test seams: only for test builds (this crate's own unit tests, or
// downstream cfg(test) users via the forwarding `test-seams` feature).
#[cfg(any(test, feature = "test-seams"))]
pub use nv_store::selector::{InMemorySelectorStore, TestSigner};

// ---------------------------------------------------------------------------
// The manager
// ---------------------------------------------------------------------------

/// In-memory view + transition engine over the selector partition.
///
/// Three selector maps model the lifecycle:
/// - `current`   = PRIMARY  = the booted selection;
/// - `committed` = SECONDARY = the rollback floor;
/// - `pending`   = in-memory staging that has **not** been written anywhere.
///
/// `generation` is the global counter of the *current* (PRIMARY) selection.
///
/// The crucial property: [`stage`](Self::stage) writes nothing — a reboot
/// between `stage` and [`seal`](Self::seal) boots the **old** selection,
/// because only `seal` touches PRIMARY. This is verified by the
/// reboot-mid-stage unit test.
pub struct SystemBankManager {
    store: Box<dyn SelectorStore>,
    signer: Box<dyn Signer>,
    /// PRIMARY / booted selection.
    current: BTreeMap<BankSet, Bank>,
    /// Generation of `current`.
    generation: u64,
    /// SECONDARY / rollback-floor selection (+ its own generation).
    committed: BTreeMap<BankSet, Bank>,
    committed_generation: u64,
    /// Booted (PRIMARY) per-component disable set — the bank sets the node must
    /// not boot, carried inside the signed blob. Mutated by
    /// [`stage_disabled`](Self::stage_disabled) and read by
    /// [`disabled`](Self::disabled). Additive: empty ⇒ blobs sign exactly as
    /// before this field existed.
    disabled: BTreeSet<BankSet>,
    /// In-memory staging; `None` until `stage` is called. Never persisted until
    /// `seal`.
    pending: Option<BTreeMap<BankSet, Bank>>,
}

impl SystemBankManager {
    /// Reconstruct on startup from the store. PRIMARY → `current` (+ its
    /// generation); SECONDARY → `committed`; `pending = None`.
    ///
    /// The store + signer are chosen at runtime (boxed trait objects) so the
    /// same manager type backs both the production stubs and a real file- or
    /// sector-backed store without a generic parameter rippling through
    /// `MachineRegistry`.
    ///
    /// A blob that fails verification (bad embedded digest or bad signature) is
    /// **rejected and treated as absent** — a forged/garbled selector must not
    /// drive boot. An absent PRIMARY (the stub case) yields empty maps at
    /// generation 0.
    pub fn load(store: Box<dyn SelectorStore>, signer: Box<dyn Signer>) -> Self {
        let primary = store.read_primary().filter(|b| b.is_valid(&*signer));
        let (current, generation, disabled) = match primary {
            Some(b) => (b.selectors, b.generation, b.disabled),
            None => (BTreeMap::new(), 0, BTreeSet::new()),
        };

        let secondary = store.read_secondary().filter(|b| b.is_valid(&*signer));
        let (committed, committed_generation) = match secondary {
            Some(b) => (b.selectors, b.generation),
            None => (BTreeMap::new(), 0),
        };

        Self {
            store,
            signer,
            current,
            generation,
            committed,
            committed_generation,
            disabled,
            pending: None,
        }
    }

    /// Stage `bank` for `set` in the **in-memory** pending selection. The first
    /// `stage` since the last `seal`/`rollback` clones `current` as the base so
    /// the staged selection is a full selector map, then overlays this entry.
    ///
    /// **Nothing is written** — neither PRIMARY nor SECONDARY changes. This is
    /// exactly why a reboot here boots the old selection.
    pub fn stage(&mut self, set: BankSet, bank: Bank) {
        let mut pending = self.pending.take().unwrap_or_else(|| self.current.clone());
        pending.insert(set, bank);
        self.pending = Some(pending);
    }

    /// Atomically promote the staged selection to PRIMARY (booted).
    ///
    /// Requires a prior `stage`. The new generation is `max(current,
    /// committed) + 1` (so it always exceeds both the booted and the floor
    /// generation). Builds + signs the blob from `pending` at that generation,
    /// writes **PRIMARY only**, then makes `pending` the new `current`.
    /// SECONDARY (the rollback floor) is deliberately untouched.
    ///
    /// Returns `false` (no-op) when there is nothing staged.
    pub fn seal(&mut self) -> bool {
        let Some(pending) = self.pending.take() else {
            return false;
        };
        let gen = self.generation.max(self.committed_generation) + 1;
        let blob = SelectorBlob::signed(gen, pending.clone(), self.disabled.clone(), &*self.signer);
        self.store.write_primary(&blob);
        self.current = pending;
        self.generation = gen;
        true
    }

    /// Set (`disabled == true`) or clear a bank set's membership in the booted
    /// (PRIMARY) disable set and re-sign PRIMARY in place.
    ///
    /// Unlike [`stage`](Self::stage) + [`seal`](Self::seal), this writes
    /// immediately: disabling a component is an idle-time admin action, not a
    /// staged boot trial. The whole blob is re-signed (all `current` selectors
    /// plus the new disable set) at the **current** generation — no
    /// anti-rollback bump, because the booted selection is unchanged and a
    /// single component disables at idle (enforced elsewhere), so there is no
    /// in-flight selector trial to disturb. SECONDARY (the rollback floor) is
    /// left untouched.
    pub fn stage_disabled(&mut self, set: BankSet, disabled: bool) {
        if disabled {
            self.disabled.insert(set);
        } else {
            self.disabled.remove(&set);
        }
        let blob = SelectorBlob::signed(
            self.generation,
            self.current.clone(),
            self.disabled.clone(),
            &*self.signer,
        );
        self.store.write_primary(&blob);
    }

    /// Promote the booted (PRIMARY) selection to the rollback floor (SECONDARY)
    /// — "the trial is over, this is now the floor". Builds + signs a blob from
    /// `current` at the *current* generation and writes it to SECONDARY.
    pub fn commit(&mut self) {
        let blob = SelectorBlob::signed(
            self.generation,
            self.current.clone(),
            self.disabled.clone(),
            &*self.signer,
        );
        self.store.write_secondary(&blob);
        self.committed = self.current.clone();
        self.committed_generation = self.generation;
    }

    /// Roll the booted (PRIMARY) selection back to the committed floor
    /// (SECONDARY). Builds a blob from `committed` at the committed generation,
    /// writes it to PRIMARY, makes `committed` the new `current`, and clears any
    /// pending staging.
    pub fn rollback(&mut self) {
        // TODO(bootloader): anti-rollback floor is SECONDARY.generation, not
        // last-seen-PRIMARY — a legitimate rollback writes an equal/lower
        // generation to PRIMARY, so the bootloader must gate on >=
        // SECONDARY.generation, not monotonic-on-PRIMARY.
        let blob = SelectorBlob::signed(
            self.committed_generation,
            self.committed.clone(),
            self.disabled.clone(),
            &*self.signer,
        );
        self.store.write_primary(&blob);
        self.current = self.committed.clone();
        self.generation = self.committed_generation;
        self.pending = None;
    }

    /// The booted bank for `set` (from PRIMARY / `current`), or `None` if the
    /// node has no selection for that set.
    pub fn active_bank(&self, set: BankSet) -> Option<Bank> {
        self.current.get(&set).copied()
    }

    /// Whether `set` is in the booted (PRIMARY) disable set — i.e. the node
    /// must not boot it. See [`BootSelector::disabled`].
    pub fn disabled(&self, set: BankSet) -> bool {
        self.disabled.contains(&set)
    }

    /// Whether the node is in a trial: the booted selection (PRIMARY) differs
    /// from the committed floor (SECONDARY).
    pub fn is_trial(&self) -> bool {
        self.current != self.committed
    }

    /// The generation of the currently-booted (PRIMARY) selection.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether the node has **no** booted selection at all (PRIMARY is the
    /// empty map). True on a fresh node whose selector has never been sealed
    /// (the stub case, or before the first seed). A later bootstrap-if-empty
    /// path uses this; harmless today.
    pub fn is_empty(&self) -> bool {
        self.current.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Shared handle + read-only selector view
// ---------------------------------------------------------------------------

/// A shared, interior-mutable handle to the one [`SystemBankManager`].
///
/// The manager is a single node-wide resource that the OTA/seed path mutates
/// (`stage`/`seal`/`commit`/`rollback`) while many readers only need
/// `active_bank` / `is_trial`. Wrapping it in `Arc<RwLock<…>>` lets
/// [`MachineRegistry`](crate::machine::MachineRegistry) hand out cheap clones:
/// a write handle ([`MachineRegistry::shared_selector`](crate::machine::MachineRegistry::shared_selector))
/// to the seed/OTA path and a read handle
/// ([`BootSelector`], via
/// [`MachineRegistry::boot_selector`](crate::machine::MachineRegistry::boot_selector))
/// to the read-mostly future consumers.
pub type SharedSystemBankState = std::sync::Arc<std::sync::RwLock<SystemBankManager>>;

/// Cheap, cloneable **read-only** view of the node's boot selector.
///
/// Hands future readers (vm-service, the providers) the two questions they
/// actually ask — "which bank does this set boot from?" and "are we in a
/// trial?" — without exposing any mutation seam. Each call takes a short-lived
/// read lock on the shared [`SystemBankManager`]; a poisoned lock is a
/// programming bug (a panic while a writer held the lock) and panics here too,
/// matching the in-memory store seams.
///
/// Additive: holding a `BootSelector` does **not** make a reader consult the
/// selector for a boot/bank decision — wiring readers to it is a later piece.
#[derive(Clone)]
pub struct BootSelector(SharedSystemBankState);

impl BootSelector {
    pub fn new(inner: SharedSystemBankState) -> Self {
        Self(inner)
    }

    /// The booted bank for `set` (PRIMARY), or `None` if the node has no
    /// selection for that set. See [`SystemBankManager::active_bank`].
    pub fn active_bank(&self, set: BankSet) -> Option<Bank> {
        self.0.read().expect("selector poisoned").active_bank(set)
    }

    /// Whether `set` is disabled in the booted selector (PRIMARY) — the node
    /// must not boot it. See [`SystemBankManager::disabled`].
    pub fn disabled(&self, set: BankSet) -> bool {
        self.0.read().expect("selector poisoned").disabled(set)
    }

    /// Whether the node is in a trial (PRIMARY differs from SECONDARY). See
    /// [`SystemBankManager::is_trial`].
    pub fn is_trial(&self) -> bool {
        self.0.read().expect("selector poisoned").is_trial()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mgr() -> SystemBankManager {
        SystemBankManager::load(Box::new(InMemorySelectorStore::new()), Box::new(TestSigner))
    }

    #[test]
    fn stage_then_seal_writes_primary_only_and_enters_trial() {
        let store = InMemorySelectorStore::new();
        let mut m = SystemBankManager::load(Box::new(store.clone()), Box::new(TestSigner));

        // Establish a committed floor at A so the staged change is observable.
        m.stage(BankSet::Vm1, Bank::A);
        assert!(m.seal());
        m.commit();
        assert!(!m.is_trial());

        // Stage B, seal.
        m.stage(BankSet::Vm1, Bank::B);
        assert!(m.seal());

        assert_eq!(m.active_bank(BankSet::Vm1), Some(Bank::B));
        assert!(m.is_trial(), "current(B) != committed(A) => trial");

        // In-memory sectors: PRIMARY == new (B), SECONDARY == old (A).
        let primary = store.read_primary().expect("primary written");
        let secondary = store.read_secondary().expect("secondary written");
        assert_eq!(primary.selectors.get(&BankSet::Vm1), Some(&Bank::B));
        assert_eq!(secondary.selectors.get(&BankSet::Vm1), Some(&Bank::A));
    }

    #[test]
    fn stage_seal_commit_clears_trial_and_both_sectors_match() {
        let store = InMemorySelectorStore::new();
        let mut m = SystemBankManager::load(Box::new(store.clone()), Box::new(TestSigner));

        m.stage(BankSet::Vm1, Bank::A);
        m.seal();
        m.commit();

        m.stage(BankSet::Vm1, Bank::B);
        m.seal();
        m.commit();

        assert!(!m.is_trial());
        let primary = store.read_primary().unwrap();
        let secondary = store.read_secondary().unwrap();
        assert_eq!(primary.selectors.get(&BankSet::Vm1), Some(&Bank::B));
        assert_eq!(secondary.selectors.get(&BankSet::Vm1), Some(&Bank::B));
    }

    #[test]
    fn stage_seal_rollback_returns_to_floor() {
        let store = InMemorySelectorStore::new();
        let mut m = SystemBankManager::load(Box::new(store.clone()), Box::new(TestSigner));

        m.stage(BankSet::Vm1, Bank::A);
        m.seal();
        m.commit(); // floor = A

        m.stage(BankSet::Vm1, Bank::B);
        m.seal(); // trial = B
        assert_eq!(m.active_bank(BankSet::Vm1), Some(Bank::B));

        m.rollback();
        assert_eq!(m.active_bank(BankSet::Vm1), Some(Bank::A));
        assert!(!m.is_trial());
        let primary = store.read_primary().unwrap();
        assert_eq!(
            primary.selectors.get(&BankSet::Vm1),
            Some(&Bank::A),
            "PRIMARY rewritten to floor on rollback"
        );
    }

    #[test]
    fn reboot_mid_stage_boots_old() {
        // The load-bearing safety property: a reboot AFTER stage but BEFORE
        // seal boots the OLD selection, because stage writes nothing.
        let store = InMemorySelectorStore::new();

        {
            let mut m = SystemBankManager::load(Box::new(store.clone()), Box::new(TestSigner));
            m.stage(BankSet::Vm1, Bank::A);
            m.seal();
            m.commit(); // committed floor = A, PRIMARY = A

            // Stage B but DO NOT seal, then drop the manager (== reboot).
            m.stage(BankSet::Vm1, Bank::B);
            assert_eq!(
                m.active_bank(BankSet::Vm1),
                Some(Bank::A),
                "pre-seal, current still reflects A"
            );
        }

        // Fresh load from the SAME store: must see the old (A) selection,
        // because the staged B was never persisted.
        let m2 = SystemBankManager::load(Box::new(store.clone()), Box::new(TestSigner));
        assert_eq!(
            m2.active_bank(BankSet::Vm1),
            Some(Bank::A),
            "reboot mid-stage boots old selection"
        );
        assert!(!m2.is_trial());
    }

    #[test]
    fn generation_increments_on_seal() {
        let mut m = mgr();
        assert_eq!(m.generation(), 0);

        m.stage(BankSet::Vm1, Bank::A);
        m.seal();
        assert_eq!(m.generation(), 1);

        m.stage(BankSet::Vm2, Bank::B);
        m.seal();
        assert_eq!(m.generation(), 2);

        // commit doesn't bump the PRIMARY generation.
        m.commit();
        assert_eq!(m.generation(), 2);
    }

    #[test]
    fn verify_failing_blob_is_rejected_on_load() {
        let store = InMemorySelectorStore::new();

        // Plant a PRIMARY blob whose signature doesn't verify under TestSigner
        // (empty sig — StubSigner would have produced this).
        let mut selectors = BTreeMap::new();
        selectors.insert(BankSet::Vm1, Bank::B);
        let generation = 9;
        let bad = SelectorBlob {
            generation,
            selectors: selectors.clone(),
            disabled: BTreeSet::new(),
            sha256: SelectorBlob::compute_sha256(generation, &selectors, &BTreeSet::new()),
            signature: Vec::new(), // invalid under TestSigner
        };
        store.write_primary(&bad);

        let m = SystemBankManager::load(Box::new(store.clone()), Box::new(TestSigner));
        // Rejected => treated as absent => empty maps, generation 0.
        assert_eq!(m.active_bank(BankSet::Vm1), None);
        assert_eq!(m.generation(), 0);

        // Also reject a blob with a tampered digest (sig over a different sha).
        let tampered = SelectorBlob {
            generation,
            selectors: selectors.clone(),
            disabled: BTreeSet::new(),
            sha256: [0u8; 32], // doesn't match contents
            signature: TestSigner.sign(&[0u8; 32]),
        };
        store.write_primary(&tampered);
        let m2 = SystemBankManager::load(Box::new(store), Box::new(TestSigner));
        assert_eq!(m2.active_bank(BankSet::Vm1), None);
    }

    #[test]
    fn stub_seams_are_loud_and_nonfatal() {
        // The production stubs must not panic and must behave as "empty,
        // accept-all": load yields empty/gen-0, seal no-ops to a None read.
        let mut m = SystemBankManager::load(Box::new(StubSelectorStore), Box::new(StubSigner));
        assert_eq!(m.generation(), 0);
        assert_eq!(m.active_bank(BankSet::Vm1), None);
        assert!(!m.seal(), "nothing staged => seal is a no-op");

        m.stage(BankSet::Vm1, Bank::B);
        assert!(m.seal()); // writes are dropped by the stub, but in-mem state advances
        assert_eq!(m.active_bank(BankSet::Vm1), Some(Bank::B));
        assert_eq!(m.generation(), 1);
    }

    /// Build a self-consistent signed blob (matching digest + TestSigner
    /// signature) for the file round-trip.
    fn blob(generation: u64, set: BankSet, bank: Bank) -> SelectorBlob {
        let mut selectors = BTreeMap::new();
        selectors.insert(set, bank);
        let sha256 = SelectorBlob::compute_sha256(generation, &selectors, &BTreeSet::new());
        SelectorBlob {
            generation,
            selectors,
            disabled: BTreeSet::new(),
            sha256,
            signature: TestSigner.sign(&sha256),
        }
    }

    #[test]
    fn file_store_round_trips_both_slots() {
        // Unique per-run dir under the system temp dir so concurrent test
        // binaries don't collide.
        let dir = std::env::temp_dir().join(format!(
            "sumo-selector-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let primary = blob(7, BankSet::Vm1, Bank::B);
        let secondary = blob(3, BankSet::Vm2, Bank::A);

        // Write through one store...
        let writer = FileSelectorStore::new(&dir);
        writer.write_primary(&primary);
        writer.write_secondary(&secondary);

        // ...read back through a fresh one (no shared in-process state).
        let reader = FileSelectorStore::new(&dir);
        assert_eq!(reader.read_primary().as_ref(), Some(&primary));
        assert_eq!(reader.read_secondary().as_ref(), Some(&secondary));

        // The slots are the named files, not the .tmp staging files.
        assert!(dir.join("primary").exists());
        assert!(dir.join("secondary").exists());

        // Digest + signature serialize as hex strings, not JSON byte arrays.
        let raw = std::fs::read_to_string(dir.join("primary")).unwrap();
        assert!(
            raw.contains("\"sha256\": \""),
            "sha256 is a hex string:\n{raw}"
        );
        assert!(
            !raw.contains("\"sha256\": ["),
            "sha256 must not be a byte array"
        );
        assert!(
            raw.contains("\"signature\": \""),
            "signature is a hex string"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
    }

    // --- signed per-component `disabled` set ---

    #[test]
    fn empty_disabled_hashes_identically_to_pre_field_encoding() {
        // (a) Additive: an empty `disabled` appends nothing to the canonical
        // bytes, so the digest equals the pre-`disabled` encoding — u64
        // generation LE, then each (BankSet.0, Bank as u8) selector pair.
        // Rebuild that legacy encoding by hand and compare.
        use sha2::{Digest, Sha256};
        let generation: u64 = 42;
        let mut selectors = BTreeMap::new();
        selectors.insert(BankSet::Os, Bank::A);
        selectors.insert(BankSet::Vm1, Bank::B);

        let mut legacy = Vec::new();
        legacy.extend_from_slice(&generation.to_le_bytes());
        for (set, bank) in &selectors {
            legacy.push(set.0);
            legacy.push(*bank as u8);
        }
        let legacy_sha: [u8; 32] = Sha256::digest(&legacy).into();

        assert_eq!(
            SelectorBlob::compute_sha256(generation, &selectors, &BTreeSet::new()),
            legacy_sha,
            "empty disabled must hash byte-for-byte as before the field existed",
        );
    }

    #[test]
    fn disabled_membership_changes_digest_and_signature() {
        // (b) A bank set in `disabled` must produce a different digest — and
        // therefore a different signature — than the enabled-only blob.
        let generation: u64 = 7;
        let mut selectors = BTreeMap::new();
        selectors.insert(BankSet::Vm1, Bank::A);

        let enabled =
            SelectorBlob::signed(generation, selectors.clone(), BTreeSet::new(), &TestSigner);
        let mut disabled = BTreeSet::new();
        disabled.insert(BankSet::Vm1);
        let with_disabled =
            SelectorBlob::signed(generation, selectors.clone(), disabled, &TestSigner);

        assert_ne!(
            enabled.sha256, with_disabled.sha256,
            "a bank set in `disabled` must change the digest",
        );
        assert_ne!(
            enabled.signature, with_disabled.signature,
            "a changed digest must change the signature",
        );
    }

    #[test]
    fn stage_disabled_round_trips_and_persists() {
        // (c) `stage_disabled` + `disabled(set)` round-trip: set, clear, re-set;
        // the disable persists into PRIMARY (survives a reload) and is visible
        // through the read-only `BootSelector` view.
        use std::sync::{Arc, RwLock};

        let store = InMemorySelectorStore::new();
        let mut m = SystemBankManager::load(Box::new(store.clone()), Box::new(TestSigner));
        m.stage(BankSet::Vm1, Bank::A);
        m.seal();

        m.stage_disabled(BankSet::Vm1, true);
        assert!(m.disabled(BankSet::Vm1));
        assert!(!m.disabled(BankSet::Vm2));
        m.stage_disabled(BankSet::Vm1, false);
        assert!(!m.disabled(BankSet::Vm1), "clearing removes membership");
        m.stage_disabled(BankSet::Vm1, true);

        // Re-sealed into PRIMARY, so a fresh load sees the disable and the
        // selection is intact.
        let m2 = SystemBankManager::load(Box::new(store.clone()), Box::new(TestSigner));
        assert!(m2.disabled(BankSet::Vm1), "disable survives reload");
        assert_eq!(m2.active_bank(BankSet::Vm1), Some(Bank::A), "selection intact");

        // Visible through the read-only BootSelector view.
        let selector = BootSelector::new(Arc::new(RwLock::new(m)));
        assert!(selector.disabled(BankSet::Vm1));
        assert!(!selector.disabled(BankSet::Vm2));
    }

    #[test]
    fn is_valid_holds_for_a_disabled_carrying_blob() {
        // (d) A blob whose signed digest covers a disable still verifies.
        let generation: u64 = 3;
        let mut selectors = BTreeMap::new();
        selectors.insert(BankSet::Vm1, Bank::B);
        let mut disabled = BTreeSet::new();
        disabled.insert(BankSet::Vm1);
        let blob = SelectorBlob::signed(generation, selectors, disabled, &TestSigner);
        assert!(blob.is_valid(&TestSigner));
    }

    #[test]
    fn legacy_json_without_disabled_key_deserializes_and_verifies() {
        // Backward-compat for the additive constraint: a selector blob written
        // before `disabled` existed had no `disabled` key AND a digest that
        // covered no disable. Simulate one by serializing an empty-disabled blob
        // and stripping the key, then confirm it round-trips to an empty set,
        // equals the original, and still verifies.
        let mut selectors = BTreeMap::new();
        selectors.insert(BankSet::Os, Bank::A);
        let legacy = SelectorBlob::signed(9, selectors, BTreeSet::new(), &TestSigner);

        let mut json = serde_json::to_value(&legacy).unwrap();
        json.as_object_mut().unwrap().remove("disabled");
        assert!(json.get("disabled").is_none(), "legacy JSON has no disabled key");

        let parsed: SelectorBlob = serde_json::from_value(json).expect("legacy blob parses");
        assert!(parsed.disabled.is_empty(), "missing key defaults to empty set");
        assert_eq!(parsed, legacy, "legacy blob equals the empty-disabled blob");
        assert!(parsed.is_valid(&TestSigner), "legacy blob still verifies");
    }
}
