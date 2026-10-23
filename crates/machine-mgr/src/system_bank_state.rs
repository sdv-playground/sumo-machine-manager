//! SystemBankState — the node's single signed, generation-counted boot
//! vector.
//!
//! This is `nv_store::NvBootState` *grown up*. Where `NvBootState` records a
//! per-bank-set `(active_bank, committed, boot_count)` triple with no global
//! ordering and no attestation, `SystemBankState` is the **one** answer to
//! "which bank does each component boot from", keyed by component id. Each
//! entry carries the bank and what was sealed into it (image sizes + SHA-256
//! by part name), and the vector as a whole carries:
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
//! — and a failed write leaves the in-memory selector where it was and is
//! reported to the caller. It is intentionally **separate** from each component's per-bank IVD
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
//! # Status: the boot / VM-launch authority
//!
//! This IS the authority for "which bank does each component boot from" on the
//! host: the OTA path
//! stages/seals/commits/rolls it back on every bank move, and boot + VM-launch
//! read it (`vm-boot::process_boot` reports from it; the host's auto-start
//! loop launches from `selector.active_bank`). `NvBootState` is NOT a
//! second boot authority — it holds the RUNNING-bank / OTA-target anchor and the
//! trial statistics (`boot_count` / `committed`), which the selector deliberately
//! does not duplicate (it derives trial structurally from PRIMARY ≠ SECONDARY).
//!
//! Storage today is [`FileSelectorStore`] (two JSON slots, human-inspectable);
//! the [`SelectorStore`] seam is the single swap point for a host store. The cache + transitions are unit-
//! tested against in-memory seams (`InMemorySelectorStore` / `TestSigner`, gated
//! behind `test-seams`). `StubSelectorStore` / `StubSigner` remain the loud
//! no-op default for builds that wire no store.

use std::collections::BTreeMap;

use nv_store::types::Bank;

// The selector STORAGE primitives moved down into `nv-store` so a lower crate
// can read the selector without depending up on `machine-mgr`. Re-exported here
// so existing `machine_mgr::system_bank_state::*` paths still resolve.
pub use nv_store::selector::{
    boot_id_digest, ComponentEntry, FileSelectorStore, ImageEntry, Outcome, Reason, Resolution,
    SelectorBlob, SelectorError, SelectorStore, Signer, SlotSelect, StubSelectorStore, StubSigner,
    Transaction,
};
// In-memory test seams: only for test builds (this crate's own unit tests, or
// downstream cfg(test) users via the forwarding `test-seams` feature).
#[cfg(any(test, feature = "test-seams"))]
pub use nv_store::selector::{InMemorySelectorStore, TestSigner};

/// Compact one-line render of a boot vector's entries for logs, e.g.
/// `{os:A vm1:B}`. Order is
/// ascending component id. Keeps the mutation logs greppable + diffable across
/// boots so a lost/reverted slot is obvious at a glance.
fn render_slots(m: &BTreeMap<String, ComponentEntry>) -> String {
    let mut s = String::from("{");
    for (i, (id, entry)) in m.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{id}:{:?}", entry.bank));
    }
    s.push('}');
    s
}

// ---------------------------------------------------------------------------
// The manager
// ---------------------------------------------------------------------------

/// What [`SystemBankManager::observe_node_boot`] saw. It counts; it never
/// decides on a limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootObservation {
    /// No armed trial: not in trial, no header, or no armed boot id.
    NotArmed,
    /// This boot is the arming boot or was already counted.
    AlreadyCounted { trial_boots: u8 },
    /// This boot was counted now; `trial_boots` is the new count.
    Counted { trial_boots: u8 },
}

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
    current: BTreeMap<String, ComponentEntry>,
    /// Generation of `current`.
    generation: u64,
    /// SECONDARY / rollback-floor selection (+ its own generation).
    committed: BTreeMap<String, ComponentEntry>,
    committed_generation: u64,
    /// PRIMARY's transaction header (the backup's is never read). Meaningful
    /// only while in trial or when it carries a resolution.
    transaction: Option<Transaction>,
    /// In-memory staging; `None` until `stage` is called. Never persisted until
    /// `seal`.
    pending: Option<BTreeMap<String, ComponentEntry>>,
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
        // A PRESENT blob that fails verification warns rather than vanishing
        // silently: the slot reads as absent (an absent PRIMARY is the host's
        // reseed-from-NV trigger), and this line is the only record of why.
        let verified = |slot: &str, blob: Option<SelectorBlob>| {
            blob.filter(|b| {
                let valid = b.is_valid(&*signer);
                if !valid {
                    tracing::warn!(
                        generation = b.generation,
                        slots = %render_slots(&b.entries),
                        "boot selector {slot} failed verification — treated as absent (will be reseeded)"
                    );
                }
                valid
            })
        };

        let primary = verified("PRIMARY", store.read_primary());
        let (current, generation, transaction) = match primary {
            Some(b) => (b.entries, b.generation, b.transaction),
            None => (BTreeMap::new(), 0, None),
        };

        let secondary = verified("SECONDARY", store.read_secondary());
        let (committed, committed_generation) = match secondary {
            Some(b) => (b.entries, b.generation),
            None => (BTreeMap::new(), 0),
        };

        Self {
            store,
            signer,
            current,
            generation,
            committed,
            committed_generation,
            transaction,
            pending: None,
        }
    }

    /// Stage `bank` (with the `images` sealed into it, by part name) for
    /// `component_id` in the **in-memory** pending selection. The first
    /// `stage` since the last `seal`/`rollback` clones `current` as the base so
    /// the staged selection is a full boot vector, then overlays this entry.
    ///
    /// **Nothing is written** — neither PRIMARY nor SECONDARY changes. This is
    /// exactly why a reboot here boots the old selection.
    pub fn stage(&mut self, component_id: &str, bank: Bank, images: BTreeMap<String, ImageEntry>) {
        let mut pending = self.pending.take().unwrap_or_else(|| self.current.clone());
        pending.insert(component_id.to_string(), ComponentEntry::new(bank, images));
        self.pending = Some(pending);
    }

    /// Atomically promote the staged selection to PRIMARY (booted).
    ///
    /// Requires a prior `stage`. The new generation is `max(current,
    /// committed) + 1` (so it always exceeds both the booted and the floor
    /// generation). Builds + signs the blob from `pending` at that generation,
    /// writes **PRIMARY only**, then makes `pending` the new `current`.
    /// SECONDARY (the rollback floor) is deliberately untouched. PRIMARY gets a
    /// fresh transaction header armed at `armed_boot_id` (`None` ⇒ unknown,
    /// stored as zero), no boots counted, no resolution.
    ///
    /// Returns `Ok(false)` (no-op, nothing written) when there is nothing
    /// staged. A failed PRIMARY write returns `Err` with `pending`, `current`
    /// and `generation` untouched, so a retry seals the same selection at the
    /// same generation.
    pub fn seal(&mut self, armed_boot_id: Option<&str>) -> Result<bool, SelectorError> {
        let Some(pending) = self.pending.clone() else {
            return Ok(false);
        };
        let gen = self.generation.max(self.committed_generation) + 1;
        let header = Transaction {
            armed_boot_id: armed_boot_id.map_or([0; 16], boot_id_digest),
            trial_boots: 0,
            counted_boot_id: [0; 16],
            resolution: None,
        };
        let blob = SelectorBlob::signed(gen, pending.clone(), Some(header.clone()), &*self.signer);
        self.store.write_primary(&blob)?;
        self.pending = None;
        self.current = pending;
        self.generation = gen;
        self.transaction = Some(header);
        tracing::info!(
            op = "seal",
            generation = gen,
            slots = %render_slots(&self.current),
            "boot-selector SEAL → PRIMARY (new booted selection)"
        );
        Ok(true)
    }

    /// Promote the booted (PRIMARY) selection to the rollback floor (SECONDARY)
    /// — "the trial is over, this is now the floor". Builds + signs a blob from
    /// `current` at the *current* generation and writes it to SECONDARY (which
    /// never carries a transaction header). PRIMARY is untouched. A failed
    /// write returns `Err` with the floor untouched. Idempotent.
    pub fn commit(&mut self) -> Result<(), SelectorError> {
        let blob = SelectorBlob::signed(self.generation, self.current.clone(), None, &*self.signer);
        self.store.write_secondary(&blob)?;
        self.committed = self.current.clone();
        self.committed_generation = self.generation;
        tracing::info!(
            op = "commit",
            generation = self.generation,
            slots = %render_slots(&self.committed),
            "boot-selector COMMIT → SECONDARY (PRIMARY copied to rollback floor)"
        );
        Ok(())
    }

    /// Roll the booted (PRIMARY) selection back to the committed floor
    /// (SECONDARY). Builds a blob from `committed` at the committed generation
    /// with the transaction header resolved as rolled back for `reason` (boot
    /// ids and count kept), writes it to PRIMARY, makes `committed` the new
    /// `current`, and clears any pending staging. A failed write returns `Err`
    /// with `current`, `generation`, the header and `pending` untouched.
    ///
    /// When the node is not in trial this writes nothing and keeps the
    /// recorded resolution (so a later verdict rollback does not overwrite the
    /// reason of an earlier one); it only drops pending staging.
    pub fn rollback(&mut self, reason: Reason) -> Result<(), SelectorError> {
        if !self.is_trial() {
            self.pending = None;
            return Ok(());
        }
        // TODO(bootloader): anti-rollback floor is SECONDARY.generation, not
        // last-seen-PRIMARY — a legitimate rollback writes an equal/lower
        // generation to PRIMARY, so the bootloader must gate on >=
        // SECONDARY.generation, not monotonic-on-PRIMARY.
        let header = Transaction {
            resolution: Some(Resolution {
                outcome: Outcome::RolledBack,
                reason,
            }),
            ..self.transaction.clone().unwrap_or(Transaction {
                armed_boot_id: [0; 16],
                trial_boots: 0,
                counted_boot_id: [0; 16],
                resolution: None,
            })
        };
        let blob = SelectorBlob::signed(
            self.committed_generation,
            self.committed.clone(),
            Some(header.clone()),
            &*self.signer,
        );
        self.store.write_primary(&blob)?;
        // WARN, not info: a rollback DISCARDS the trial (overwrites PRIMARY with
        // the SECONDARY floor). If a freshly-sealed VM slot vanishes across a
        // reboot, THIS line firing is the smoking gun (active revert); its
        // ABSENCE means the loss was cache/durability, not a rollback.
        tracing::warn!(
            op = "rollback",
            generation = self.committed_generation,
            slots = %render_slots(&self.committed),
            "boot-selector ROLLBACK → PRIMARY overwritten with SECONDARY floor (trial discarded)"
        );
        self.current = self.committed.clone();
        self.generation = self.committed_generation;
        self.transaction = Some(header);
        self.pending = None;
        Ok(())
    }

    /// Count this node boot against the armed trial. `NotArmed` when the node
    /// is not in trial or PRIMARY carries no armed boot id; `AlreadyCounted`
    /// when `current_boot_id` is the arming boot or the last counted one (so a
    /// process restart within one boot counts nothing); otherwise the count
    /// goes up by one (saturating) and PRIMARY is rewritten at the same
    /// generation with the same entries — persisted first, memory after, so a
    /// failed write leaves everything untouched. Never decides on a limit.
    pub fn observe_node_boot(
        &mut self,
        current_boot_id: &str,
    ) -> Result<BootObservation, SelectorError> {
        let Some(t) = self.transaction.as_ref().filter(|_| self.is_trial()) else {
            return Ok(BootObservation::NotArmed);
        };
        if t.armed_boot_id == [0; 16] {
            return Ok(BootObservation::NotArmed);
        }
        let id = boot_id_digest(current_boot_id);
        if id == t.armed_boot_id || id == t.counted_boot_id {
            return Ok(BootObservation::AlreadyCounted {
                trial_boots: t.trial_boots,
            });
        }
        let header = Transaction {
            trial_boots: t.trial_boots.saturating_add(1),
            counted_boot_id: id,
            ..t.clone()
        };
        let blob = SelectorBlob::signed(
            self.generation,
            self.current.clone(),
            Some(header.clone()),
            &*self.signer,
        );
        self.store.write_primary(&blob)?;
        let trial_boots = header.trial_boots;
        tracing::info!(
            op = "count_boot",
            generation = self.generation,
            trial_boots,
            "boot-selector trial boot counted → PRIMARY"
        );
        self.transaction = Some(header);
        Ok(BootObservation::Counted { trial_boots })
    }

    /// PRIMARY's transaction header, if it carries one.
    pub fn transaction(&self) -> Option<&Transaction> {
        self.transaction.as_ref()
    }

    /// Whether the node has rebooted since the trial was armed: `None` when
    /// there is no header, the armed id is unknown, or `current` is `None`.
    pub fn rebooted_since_arming(&self, current: Option<&str>) -> Option<bool> {
        let t = self.transaction.as_ref()?;
        if t.armed_boot_id == [0; 16] {
            return None;
        }
        Some(t.armed_boot_id != boot_id_digest(current?))
    }

    /// The booted bank for `component_id` (from PRIMARY / `current`), or `None`
    /// if the node has no selection for that component.
    pub fn active_bank(&self, component_id: &str) -> Option<Bank> {
        self.current.get(component_id).map(|e| e.bank)
    }

    /// The booted entry for `component_id` (from PRIMARY / `current`), or
    /// `None` if the node has no selection for that component.
    pub fn entry(&self, component_id: &str) -> Option<&ComponentEntry> {
        self.current.get(component_id)
    }

    /// The committed-floor entry for `component_id` (from SECONDARY /
    /// `committed`), or `None` if the floor has no selection for it.
    pub fn committed_entry(&self, component_id: &str) -> Option<&ComponentEntry> {
        self.committed.get(component_id)
    }

    /// Whether `component_id` is in a trial: its booted entry (PRIMARY) differs
    /// from its committed-floor entry (SECONDARY). An absent floor entry counts
    /// as different; a component with no booted entry is never in a trial.
    pub fn component_in_trial(&self, component_id: &str) -> bool {
        match self.entry(component_id) {
            Some(entry) => self.committed_entry(component_id) != Some(entry),
            None => false,
        }
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
/// actually ask — "which bank does this component boot from?" and "are we in a
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

    /// The booted bank for `component_id` (PRIMARY), or `None` if the node has
    /// no selection for that component. See [`SystemBankManager::active_bank`].
    pub fn active_bank(&self, component_id: &str) -> Option<Bank> {
        self.0
            .read()
            .expect("selector poisoned")
            .active_bank(component_id)
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
    use nv_store::slots;

    fn mgr() -> SystemBankManager {
        SystemBankManager::load(Box::new(InMemorySelectorStore::new()), Box::new(TestSigner))
    }

    #[test]
    fn stage_then_seal_writes_primary_only_and_enters_trial() {
        let store = InMemorySelectorStore::new();
        let mut m = SystemBankManager::load(Box::new(store.clone()), Box::new(TestSigner));

        // Establish a committed floor at A so the staged change is observable.
        m.stage("vm1", Bank::A, BTreeMap::new());
        assert!(m.seal(None).unwrap());
        m.commit().unwrap();
        assert!(!m.is_trial());

        // Stage B, seal.
        m.stage("vm1", Bank::B, BTreeMap::new());
        assert!(m.seal(None).unwrap());

        assert_eq!(m.active_bank("vm1"), Some(Bank::B));
        assert!(m.is_trial(), "current(B) != committed(A) => trial");

        // In-memory sectors: PRIMARY == new (B), SECONDARY == old (A).
        let primary = store.read_primary().expect("primary written");
        let secondary = store.read_secondary().expect("secondary written");
        assert_eq!(primary.entries["vm1"].bank, Bank::B);
        assert_eq!(secondary.entries["vm1"].bank, Bank::A);
    }

    #[test]
    fn stage_seal_commit_clears_trial_and_both_sectors_match() {
        let store = InMemorySelectorStore::new();
        let mut m = SystemBankManager::load(Box::new(store.clone()), Box::new(TestSigner));

        m.stage("vm1", Bank::A, BTreeMap::new());
        m.seal(None).unwrap();
        m.commit().unwrap();

        m.stage("vm1", Bank::B, BTreeMap::new());
        m.seal(None).unwrap();
        m.commit().unwrap();

        assert!(!m.is_trial());
        let primary = store.read_primary().unwrap();
        let secondary = store.read_secondary().unwrap();
        assert_eq!(primary.entries["vm1"].bank, Bank::B);
        assert_eq!(secondary.entries["vm1"].bank, Bank::B);
    }

    #[test]
    fn stage_seal_rollback_returns_to_floor() {
        let store = InMemorySelectorStore::new();
        let mut m = SystemBankManager::load(Box::new(store.clone()), Box::new(TestSigner));

        m.stage("vm1", Bank::A, BTreeMap::new());
        m.seal(None).unwrap();
        m.commit().unwrap(); // floor = A

        m.stage("vm1", Bank::B, BTreeMap::new());
        m.seal(None).unwrap(); // trial = B
        assert_eq!(m.active_bank("vm1"), Some(Bank::B));

        m.rollback(Reason::Verdict).unwrap();
        assert_eq!(m.active_bank("vm1"), Some(Bank::A));
        assert!(!m.is_trial());
        let primary = store.read_primary().unwrap();
        assert_eq!(
            primary.entries["vm1"].bank,
            Bank::A,
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
            m.stage("vm1", Bank::A, BTreeMap::new());
            m.seal(None).unwrap();
            m.commit().unwrap(); // committed floor = A, PRIMARY = A

            // Stage B but DO NOT seal, then drop the manager (== reboot).
            m.stage("vm1", Bank::B, BTreeMap::new());
            assert_eq!(
                m.active_bank("vm1"),
                Some(Bank::A),
                "pre-seal, current still reflects A"
            );
        }

        // Fresh load from the SAME store: must see the old (A) selection,
        // because the staged B was never persisted.
        let m2 = SystemBankManager::load(Box::new(store.clone()), Box::new(TestSigner));
        assert_eq!(
            m2.active_bank("vm1"),
            Some(Bank::A),
            "reboot mid-stage boots old selection"
        );
        assert!(!m2.is_trial());
    }

    #[test]
    fn component_in_trial_true_when_floor_lacks_entry() {
        let mut m = mgr();
        m.stage("vm1", Bank::A, BTreeMap::new());
        m.seal(None).unwrap();
        assert!(m.committed_entry("vm1").is_none());
        assert!(m.component_in_trial("vm1"));
    }

    #[test]
    fn component_in_trial_true_when_banks_differ() {
        let mut m = mgr();
        m.stage("vm1", Bank::A, BTreeMap::new());
        m.stage("vm2", Bank::A, BTreeMap::new());
        m.seal(None).unwrap();
        m.commit().unwrap();
        m.stage("vm1", Bank::B, BTreeMap::new());
        m.seal(None).unwrap();
        assert_eq!(m.entry("vm1").map(|e| e.bank), Some(Bank::B));
        assert_eq!(m.committed_entry("vm1").map(|e| e.bank), Some(Bank::A));
        assert!(m.component_in_trial("vm1"));
        assert!(!m.component_in_trial("vm2"), "vm2 unchanged since commit");
    }

    #[test]
    fn component_in_trial_false_when_equal() {
        let mut m = mgr();
        m.stage("vm1", Bank::B, BTreeMap::new());
        m.seal(None).unwrap();
        m.commit().unwrap();
        assert!(!m.component_in_trial("vm1"));
    }

    #[test]
    fn component_in_trial_false_when_primary_lacks_entry() {
        let mut m = mgr();
        m.stage("vm1", Bank::A, BTreeMap::new());
        m.seal(None).unwrap();
        m.commit().unwrap();
        assert!(m.entry("vm2").is_none());
        assert!(!m.component_in_trial("vm2"));
    }

    #[test]
    fn generation_increments_on_seal() {
        let mut m = mgr();
        assert_eq!(m.generation(), 0);

        m.stage("vm1", Bank::A, BTreeMap::new());
        m.seal(None).unwrap();
        assert_eq!(m.generation(), 1);

        m.stage("vm2", Bank::B, BTreeMap::new());
        m.seal(None).unwrap();
        assert_eq!(m.generation(), 2);

        // commit doesn't bump the PRIMARY generation.
        m.commit().unwrap();
        assert_eq!(m.generation(), 2);
    }

    #[test]
    fn verify_failing_blob_is_rejected_on_load() {
        let store = InMemorySelectorStore::new();

        // Plant a PRIMARY blob whose signature doesn't verify under TestSigner
        // (empty sig — StubSigner would have produced this).
        let mut entries = BTreeMap::new();
        entries.insert(
            "vm1".to_string(),
            ComponentEntry::new(Bank::B, BTreeMap::new()),
        );
        let generation = 9;
        let bad = SelectorBlob {
            generation,
            entries: entries.clone(),
            transaction: None,
            sha256: SelectorBlob::compute_sha256(generation, &entries, None),
            signature: Vec::new(), // invalid under TestSigner
            selectors: None,
        };
        store.write_primary(&bad).unwrap();

        let m = SystemBankManager::load(Box::new(store.clone()), Box::new(TestSigner));
        // Rejected => treated as absent => empty maps, generation 0.
        assert_eq!(m.active_bank("vm1"), None);
        assert_eq!(m.generation(), 0);

        // Also reject a blob with a tampered digest (sig over a different sha).
        let tampered = SelectorBlob {
            generation,
            entries: entries.clone(),
            transaction: None,
            sha256: [0u8; 32], // doesn't match contents
            signature: TestSigner.sign(&[0u8; 32]),
            selectors: None,
        };
        store.write_primary(&tampered).unwrap();
        let m2 = SystemBankManager::load(Box::new(store), Box::new(TestSigner));
        assert_eq!(m2.active_bank("vm1"), None);
    }

    #[test]
    fn stub_seams_are_loud_and_nonfatal() {
        // The production stubs must not panic and must behave as "empty,
        // accept-all": load yields empty/gen-0, seal no-ops to a None read.
        let mut m = SystemBankManager::load(Box::new(StubSelectorStore), Box::new(StubSigner));
        assert_eq!(m.generation(), 0);
        assert_eq!(m.active_bank("vm1"), None);
        assert!(!m.seal(None).unwrap(), "nothing staged => seal is a no-op");

        m.stage("vm1", Bank::B, BTreeMap::new());
        assert!(m.seal(None).unwrap()); // writes are dropped by the stub, but in-mem state advances
        assert_eq!(m.active_bank("vm1"), Some(Bank::B));
        assert_eq!(m.generation(), 1);
    }

    // --- a failed store write leaves the in-memory selector where it was ---

    #[test]
    fn failed_seal_leaves_state_untouched_and_retry_uses_same_generation() {
        let store = InMemorySelectorStore::new();
        let mut m = SystemBankManager::load(Box::new(store.clone()), Box::new(TestSigner));
        m.stage("vm1", Bank::A, BTreeMap::new());
        m.seal(None).unwrap();
        m.commit().unwrap(); // floor = A at gen 1

        m.stage("vm1", Bank::B, BTreeMap::new());
        store.set_fail_writes(true);
        assert!(m.seal(None).is_err());
        assert_eq!(m.active_bank("vm1"), Some(Bank::A), "current untouched");
        assert_eq!(m.generation(), 1, "generation untouched");
        assert!(m.pending.is_some(), "pending kept for the retry");
        assert_eq!(store.read_primary().unwrap().generation, 1);

        store.set_fail_writes(false);
        assert!(m.seal(None).unwrap());
        assert_eq!(m.active_bank("vm1"), Some(Bank::B));
        assert_eq!(
            m.generation(),
            2,
            "same gen the first attempt would have had"
        );
        assert!(m.pending.is_none());
        assert_eq!(store.read_primary().unwrap().generation, 2);
    }

    #[test]
    fn failed_commit_leaves_floor_untouched() {
        let store = InMemorySelectorStore::new();
        let mut m = SystemBankManager::load(Box::new(store.clone()), Box::new(TestSigner));
        m.stage("vm1", Bank::A, BTreeMap::new());
        m.seal(None).unwrap();
        m.commit().unwrap();
        m.stage("vm1", Bank::B, BTreeMap::new());
        m.seal(None).unwrap(); // trial B over floor A

        store.set_fail_writes(true);
        assert!(m.commit().is_err());
        assert_eq!(m.committed["vm1"].bank, Bank::A);
        assert_eq!(m.committed_generation, 1);
        assert!(m.is_trial(), "still in trial");
        assert_eq!(store.read_secondary().unwrap().generation, 1);
    }

    #[test]
    fn failed_rollback_leaves_state_untouched() {
        let store = InMemorySelectorStore::new();
        let mut m = SystemBankManager::load(Box::new(store.clone()), Box::new(TestSigner));
        m.stage("vm1", Bank::A, BTreeMap::new());
        m.seal(None).unwrap();
        m.commit().unwrap();
        m.stage("vm1", Bank::B, BTreeMap::new());
        m.seal(None).unwrap(); // trial B at gen 2
        m.stage("vm2", Bank::B, BTreeMap::new()); // something pending

        store.set_fail_writes(true);
        assert!(m.rollback(Reason::Verdict).is_err());
        assert_eq!(m.active_bank("vm1"), Some(Bank::B));
        assert_eq!(m.generation(), 2);
        assert!(m.pending.is_some(), "pending untouched");
        assert_eq!(store.read_primary().unwrap().generation, 2);
    }

    #[test]
    fn seal_with_nothing_staged_writes_nothing() {
        let store = InMemorySelectorStore::new();
        let mut m = SystemBankManager::load(Box::new(store.clone()), Box::new(TestSigner));
        assert!(!m.seal(None).unwrap());
        assert_eq!(store.write_count(), 0);
        assert!(store.read_primary().is_none());
    }

    #[test]
    fn commit_twice_is_ok_with_one_write_each() {
        let store = InMemorySelectorStore::new();
        let mut m = SystemBankManager::load(Box::new(store.clone()), Box::new(TestSigner));
        m.stage("vm1", Bank::A, BTreeMap::new());
        m.seal(None).unwrap();
        let before = store.write_count();

        m.commit().unwrap();
        assert_eq!(store.write_count(), before + 1);
        m.commit().unwrap();
        assert_eq!(store.write_count(), before + 2);
        assert!(!m.is_trial());
        assert_eq!(store.read_secondary().unwrap().generation, 1);
    }

    // --- the PRIMARY transaction header ---

    /// A node in trial: floor vm1=A committed, then vm1=B sealed armed at
    /// `armed`.
    fn armed_trial(armed: Option<&str>) -> (InMemorySelectorStore, SystemBankManager) {
        let store = InMemorySelectorStore::new();
        let mut m = SystemBankManager::load(Box::new(store.clone()), Box::new(TestSigner));
        m.stage("vm1", Bank::A, BTreeMap::new());
        m.seal(None).unwrap();
        m.commit().unwrap();
        m.stage("vm1", Bank::B, BTreeMap::new());
        m.seal(armed).unwrap();
        (store, m)
    }

    #[test]
    fn seal_arms_the_primary_header_and_the_backup_never_carries_one() {
        let (store, mut m) = armed_trial(Some("boot-a"));
        let want = Transaction {
            armed_boot_id: boot_id_digest("boot-a"),
            trial_boots: 0,
            counted_boot_id: [0; 16],
            resolution: None,
        };
        assert_eq!(m.transaction(), Some(&want));
        assert_eq!(store.read_primary().unwrap().transaction, Some(want));

        m.commit().unwrap();
        assert_eq!(store.read_secondary().unwrap().transaction, None);
        assert!(
            store.read_primary().unwrap().transaction.is_some(),
            "PRIMARY untouched"
        );

        // The header survives a reload and stays inside the digest.
        let m2 = SystemBankManager::load(Box::new(store.clone()), Box::new(TestSigner));
        assert_eq!(m2.transaction(), m.transaction());
        let mut tampered = store.read_primary().unwrap();
        tampered.transaction.as_mut().unwrap().trial_boots = 9;
        assert!(!tampered.is_valid(&TestSigner), "header is signed");
    }

    #[test]
    fn rollback_records_the_reason_and_is_a_no_op_when_not_in_trial() {
        let (store, mut m) = armed_trial(Some("boot-a"));
        m.rollback(Reason::TrialBootLimit).unwrap();
        let resolved = Some(Resolution {
            outcome: Outcome::RolledBack,
            reason: Reason::TrialBootLimit,
        });
        let primary = store.read_primary().unwrap();
        assert_eq!(primary.entries["vm1"].bank, Bank::A);
        let t = primary.transaction.unwrap();
        assert_eq!(t.resolution, resolved);
        assert_eq!(t.armed_boot_id, boot_id_digest("boot-a"), "ids kept");
        assert_eq!(m.transaction().unwrap().resolution, resolved);

        // Not in trial any more: a verdict rollback writes nothing and keeps
        // the recorded reason.
        let writes = store.write_count();
        m.rollback(Reason::Verdict).unwrap();
        assert_eq!(store.write_count(), writes);
        assert_eq!(m.transaction().unwrap().resolution, resolved);
        assert_eq!(
            store
                .read_primary()
                .unwrap()
                .transaction
                .unwrap()
                .resolution,
            resolved
        );
    }

    #[test]
    fn rebooted_since_arming_follows_the_header() {
        assert_eq!(mgr().rebooted_since_arming(Some("x")), None, "no header");
        let (_, m) = armed_trial(None);
        assert_eq!(m.rebooted_since_arming(Some("x")), None, "armed unknown");
        let (_, m) = armed_trial(Some("boot-a"));
        assert_eq!(m.rebooted_since_arming(None), None);
        assert_eq!(m.rebooted_since_arming(Some("boot-a")), Some(false));
        assert_eq!(m.rebooted_since_arming(Some("boot-b")), Some(true));
    }

    #[test]
    fn observe_node_boot_not_armed_outside_a_trial_or_without_an_armed_id() {
        let mut m = mgr();
        m.stage("vm1", Bank::A, BTreeMap::new());
        m.seal(Some("boot-a")).unwrap();
        m.commit().unwrap();
        assert_eq!(
            m.observe_node_boot("boot-b").unwrap(),
            BootObservation::NotArmed
        );

        let (_, mut m) = armed_trial(None);
        assert_eq!(
            m.observe_node_boot("boot-b").unwrap(),
            BootObservation::NotArmed
        );
    }

    #[test]
    fn observe_node_boot_counts_each_distinct_boot_once() {
        let (store, mut m) = armed_trial(Some("boot-a"));
        let gen = m.generation();
        assert_eq!(
            m.observe_node_boot("boot-a").unwrap(),
            BootObservation::AlreadyCounted { trial_boots: 0 },
            "the arming boot is not a trial boot"
        );
        assert_eq!(
            m.observe_node_boot("boot-b").unwrap(),
            BootObservation::Counted { trial_boots: 1 }
        );
        let writes = store.write_count();
        assert_eq!(
            m.observe_node_boot("boot-b").unwrap(),
            BootObservation::AlreadyCounted { trial_boots: 1 }
        );
        assert_eq!(store.write_count(), writes, "a repeat writes nothing");
        assert_eq!(
            m.observe_node_boot("boot-c").unwrap(),
            BootObservation::Counted { trial_boots: 2 }
        );

        let primary = store.read_primary().unwrap();
        assert_eq!(primary.generation, gen, "same generation");
        assert_eq!(primary.entries["vm1"].bank, Bank::B, "same entries");
        let t = primary.transaction.clone().unwrap();
        assert_eq!(t.trial_boots, 2);
        assert_eq!(t.counted_boot_id, boot_id_digest("boot-c"));
        assert!(primary.is_valid(&TestSigner));
        assert!(m.is_trial());
    }

    #[test]
    fn failed_observe_node_boot_leaves_memory_unchanged() {
        let (store, mut m) = armed_trial(Some("boot-a"));
        let before = m.transaction().cloned();
        store.set_fail_writes(true);
        assert!(m.observe_node_boot("boot-b").is_err());
        assert_eq!(m.transaction().cloned(), before);
        store.set_fail_writes(false);
        assert_eq!(
            m.observe_node_boot("boot-b").unwrap(),
            BootObservation::Counted { trial_boots: 1 }
        );
    }

    /// Build a self-consistent signed blob (matching digest + TestSigner
    /// signature) for the file round-trip.
    fn blob(generation: u64, id: &str, bank: Bank) -> SelectorBlob {
        let images = BTreeMap::from([(
            "kernel".to_string(),
            ImageEntry {
                size: 4096,
                sha256: [0xAB; 32],
            },
        )]);
        let mut entries = BTreeMap::new();
        entries.insert(id.to_string(), ComponentEntry::new(bank, images));
        SelectorBlob::signed(generation, entries, None, &TestSigner)
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

        let primary = blob(7, "vm1", Bank::B);
        let secondary = blob(3, "vm2", Bank::A);

        // Write through one store...
        let writer = FileSelectorStore::new(&dir);
        writer.write_primary(&primary).unwrap();
        writer.write_secondary(&secondary).unwrap();

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
        // One key per line; no legacy slot map unless configured.
        assert!(
            raw.contains("\"size\": 4096,\n"),
            "image size is a number:\n{raw}"
        );
        assert!(!raw.contains("selectors"), "no legacy slot map:\n{raw}");

        std::fs::remove_dir_all(&dir).expect("cleanup temp dir");
    }

    // --- blobs signed over the retired per-slot encoding ---

    #[test]
    fn legacy_slot_blob_is_rejected_on_load() {
        // A blob correctly signed over the OLD encoding — `[set, bank]` per
        // slot, the selection carried only in the slot map — no longer
        // verifies: the digest is over the entries, and there are none. Both
        // slots read as absent, so the node looks unseeded and the host
        // reseeds it from NV.
        use sha2::{Digest, Sha256};

        let generation: u64 = 5;
        let mut legacy = generation.to_le_bytes().to_vec();
        legacy.extend_from_slice(&[slots::VM1.0, Bank::A as u8]);
        let sha256: [u8; 32] = Sha256::digest(&legacy).into();
        let mut selectors = BTreeMap::new();
        selectors.insert(slots::VM1, SlotSelect::new(Bank::A));
        let blob = SelectorBlob {
            generation,
            entries: BTreeMap::new(),
            transaction: None,
            sha256,
            signature: TestSigner.sign(&sha256),
            selectors: Some(selectors),
        };
        assert!(
            TestSigner.verify(&blob.sha256, &blob.signature),
            "the signature itself is good — only the digest is stale"
        );

        let store = InMemorySelectorStore::new();
        store.write_primary(&blob).unwrap();
        store.write_secondary(&blob).unwrap();

        let m = SystemBankManager::load(Box::new(store), Box::new(TestSigner));
        assert!(m.is_empty(), "PRIMARY rejected");
        assert_eq!(m.generation(), 0);
        // current is empty, so a trial would mean SECONDARY survived.
        assert!(!m.is_trial(), "SECONDARY rejected");
    }

    #[test]
    fn slot_json_with_legacy_enabled_key_still_parses() {
        // A slot written with the retired `enabled` key still parses (unknown
        // keys are ignored); its blob then fails `is_valid`, not the parse.
        let json = serde_json::json!({ "bank": "A", "enabled": false });
        let sel: SlotSelect = serde_json::from_value(json).expect("slot parses");
        assert_eq!(sel, SlotSelect { bank: Bank::A });
    }
}
