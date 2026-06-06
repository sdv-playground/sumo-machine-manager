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
//! # Status: additive shadow, not yet load-bearing
//!
//! The physical sector layout for the selector partition is a **bootloader
//! contract that does not exist yet**. So the production [`SelectorStore`] and
//! [`Signer`] here are loud stubs ([`StubSelectorStore`] / [`StubSigner`]) that
//! warn and no-op. The cache + state transitions are fully real and unit-tested
//! against in-memory seams ([`InMemorySelectorStore`] / [`TestSigner`]) so the
//! state machine is correct the day the sector contract lands — at which point
//! the stubs are swapped for real eMMC sector I/O + HSM signing and this becomes
//! the authority. Until then the existing per-component commit/rollback
//! (`BankProvider` + `NvBootState`) remains the authority; this runs alongside.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use nv_store::types::{Bank, BankSet};

/// The on-medium selector record: which bank each component boots from, at a
/// given global generation, signed.
///
/// `selectors` is a [`BTreeMap`] precisely so the canonical byte encoding used
/// for [`Self::sha256`] is **stable** regardless of insertion order — a
/// `HashMap` would hash differently run to run and the signature would not
/// reproduce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectorBlob {
    /// Global anti-rollback generation. Monotonic on `seal`.
    pub generation: u64,
    /// `BankSet -> Bank` boot selection, canonically ordered.
    pub selectors: BTreeMap<BankSet, Bank>,
    /// SHA-256 over the canonical `(generation, selectors)` bytes — the digest
    /// the signature covers.
    pub sha256: [u8; 32],
    /// Detached signature over [`Self::sha256`] (HSM `Signer::sign`).
    pub signature: Vec<u8>,
}

impl SelectorBlob {
    /// Build the canonical, order-stable byte encoding of `(generation,
    /// selectors)` that [`Self::sha256`] digests and the signature covers.
    ///
    /// Layout (little-endian, fixed-width — no length-prefixed text, so it is
    /// reproducible byte-for-byte): the u64 generation, then each
    /// `(BankSet.0: u8, Bank: u8)` pair in `BTreeMap` (ascending `BankSet`)
    /// order. `BankSet` is a `u8` newtype and `Bank` is `repr(u8)`, so two
    /// bytes per entry suffice.
    pub fn canonical_bytes(generation: u64, selectors: &BTreeMap<BankSet, Bank>) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + selectors.len() * 2);
        buf.extend_from_slice(&generation.to_le_bytes());
        for (set, bank) in selectors {
            buf.push(set.0);
            buf.push(*bank as u8);
        }
        buf
    }

    /// Compute the canonical SHA-256 for `(generation, selectors)`.
    pub fn compute_sha256(generation: u64, selectors: &BTreeMap<BankSet, Bank>) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(Self::canonical_bytes(generation, selectors)).into()
    }

    /// Build + sign a blob for `selectors` at `generation` using `signer`.
    fn signed(
        generation: u64,
        selectors: BTreeMap<BankSet, Bank>,
        signer: &dyn Signer,
    ) -> SelectorBlob {
        let sha256 = Self::compute_sha256(generation, &selectors);
        let signature = signer.sign(&sha256);
        SelectorBlob {
            generation,
            selectors,
            sha256,
            signature,
        }
    }

    /// Verify both the embedded digest (recompute over the contents) and the
    /// signature over that digest. A blob whose `sha256` doesn't match its own
    /// contents, or whose signature doesn't verify, is rejected.
    fn is_valid(&self, signer: &dyn Signer) -> bool {
        let recomputed = Self::compute_sha256(self.generation, &self.selectors);
        recomputed == self.sha256 && signer.verify(&self.sha256, &self.signature)
    }
}

// ---------------------------------------------------------------------------
// Seams: storage + signing
// ---------------------------------------------------------------------------

/// The two-slot persistence seam for the selector partition: a PRIMARY (booted)
/// slot and a SECONDARY (rollback floor) slot.
///
/// The production impl writes raw eMMC sectors; the test impl keeps two
/// in-memory cells. Keeping this a trait makes the manager's cache + transition
/// logic testable now and leaves the hardware edge swappable when the bootloader
/// sector contract lands.
pub trait SelectorStore: Send + Sync {
    fn read_primary(&self) -> Option<SelectorBlob>;
    fn write_primary(&self, blob: &SelectorBlob);
    fn read_secondary(&self) -> Option<SelectorBlob>;
    fn write_secondary(&self, blob: &SelectorBlob);
}

/// The attestation seam: sign / verify the selector digest. The production impl
/// is the HSM's selector-signing key; the test impl is a trivial deterministic
/// transform.
pub trait Signer: Send + Sync {
    fn sign(&self, sha: &[u8; 32]) -> Vec<u8>;
    fn verify(&self, sha: &[u8; 32], sig: &[u8]) -> bool;
}

// ---------------------------------------------------------------------------
// Production stubs — loud, non-fatal (additive shadow, not yet load-bearing)
// ---------------------------------------------------------------------------

/// Production [`SelectorStore`] placeholder. Every method warns loudly and does
/// nothing: reads return `None`, writes are dropped. **Non-fatal on purpose** —
/// this is an additive shadow of the existing per-component boot state, not yet
/// the boot authority, so a node with only the stub wired keeps booting via
/// `NvBootState`. Replaced by real sector I/O when the bootloader publishes the
/// selector partition layout.
#[derive(Debug, Default, Clone)]
pub struct StubSelectorStore;

impl SelectorStore for StubSelectorStore {
    fn read_primary(&self) -> Option<SelectorBlob> {
        tracing::warn!(
            "TODO(bootloader): SystemBankState sector I/O unimplemented — selector partition layout pending bootloader support"
        );
        None
    }
    fn write_primary(&self, _blob: &SelectorBlob) {
        tracing::warn!(
            "TODO(bootloader): SystemBankState sector I/O unimplemented — selector partition layout pending bootloader support"
        );
    }
    fn read_secondary(&self) -> Option<SelectorBlob> {
        tracing::warn!(
            "TODO(bootloader): SystemBankState sector I/O unimplemented — selector partition layout pending bootloader support"
        );
        None
    }
    fn write_secondary(&self, _blob: &SelectorBlob) {
        tracing::warn!(
            "TODO(bootloader): SystemBankState sector I/O unimplemented — selector partition layout pending bootloader support"
        );
    }
}

/// Production [`Signer`] placeholder. `sign` returns an empty signature and
/// `verify` accepts anything — both warn. Replaced by the HSM selector-signing
/// key when the attestation path is wired.
#[derive(Debug, Default, Clone)]
pub struct StubSigner;

impl Signer for StubSigner {
    fn sign(&self, _sha: &[u8; 32]) -> Vec<u8> {
        tracing::warn!(
            "TODO(hsm): SystemBankState selector signing unimplemented — returning empty signature"
        );
        Vec::new()
    }
    fn verify(&self, _sha: &[u8; 32], _sig: &[u8]) -> bool {
        tracing::warn!(
            "TODO(hsm): SystemBankState selector verification unimplemented — accepting signature"
        );
        true
    }
}

// ---------------------------------------------------------------------------
// In-memory test seams — real sectors + deterministic sign/verify
// ---------------------------------------------------------------------------

/// In-memory [`SelectorStore`]: two real cells behind a mutex. Lets the
/// [`SystemBankManager`] be exercised end-to-end (including the
/// reboot-mid-stage case: drop the manager, `load` a fresh one from the *same*
/// store) without any hardware.
#[derive(Debug, Default, Clone)]
pub struct InMemorySelectorStore {
    primary: std::sync::Arc<std::sync::Mutex<Option<SelectorBlob>>>,
    secondary: std::sync::Arc<std::sync::Mutex<Option<SelectorBlob>>>,
}

impl InMemorySelectorStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SelectorStore for InMemorySelectorStore {
    fn read_primary(&self) -> Option<SelectorBlob> {
        self.primary.lock().expect("primary poisoned").clone()
    }
    fn write_primary(&self, blob: &SelectorBlob) {
        *self.primary.lock().expect("primary poisoned") = Some(blob.clone());
    }
    fn read_secondary(&self) -> Option<SelectorBlob> {
        self.secondary.lock().expect("secondary poisoned").clone()
    }
    fn write_secondary(&self, blob: &SelectorBlob) {
        *self.secondary.lock().expect("secondary poisoned") = Some(blob.clone());
    }
}

/// Deterministic test [`Signer`]: the "signature" is the digest with every byte
/// XOR-ed by `0xA5`. `verify` recomputes and compares — so a tampered digest or
/// a forged signature is actually rejected, which is what the
/// verify-failing-blob test relies on.
#[derive(Debug, Default, Clone)]
pub struct TestSigner;

impl TestSigner {
    fn transform(sha: &[u8; 32]) -> Vec<u8> {
        sha.iter().map(|b| b ^ 0xA5).collect()
    }
}

impl Signer for TestSigner {
    fn sign(&self, sha: &[u8; 32]) -> Vec<u8> {
        Self::transform(sha)
    }
    fn verify(&self, sha: &[u8; 32], sig: &[u8]) -> bool {
        sig == Self::transform(sha).as_slice()
    }
}

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
pub struct SystemBankManager<S: SelectorStore, K: Signer> {
    store: S,
    signer: K,
    /// PRIMARY / booted selection.
    current: BTreeMap<BankSet, Bank>,
    /// Generation of `current`.
    generation: u64,
    /// SECONDARY / rollback-floor selection (+ its own generation).
    committed: BTreeMap<BankSet, Bank>,
    committed_generation: u64,
    /// In-memory staging; `None` until `stage` is called. Never persisted until
    /// `seal`.
    pending: Option<BTreeMap<BankSet, Bank>>,
}

impl<S: SelectorStore, K: Signer> SystemBankManager<S, K> {
    /// Reconstruct on startup from the store. PRIMARY → `current` (+ its
    /// generation); SECONDARY → `committed`; `pending = None`.
    ///
    /// A blob that fails verification (bad embedded digest or bad signature) is
    /// **rejected and treated as absent** — a forged/garbled selector must not
    /// drive boot. An absent PRIMARY (the stub case) yields empty maps at
    /// generation 0.
    pub fn load(store: S, signer: K) -> Self {
        let primary = store.read_primary().filter(|b| b.is_valid(&signer));
        let (current, generation) = match primary {
            Some(b) => (b.selectors, b.generation),
            None => (BTreeMap::new(), 0),
        };

        let secondary = store.read_secondary().filter(|b| b.is_valid(&signer));
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
        let blob = SelectorBlob::signed(gen, pending.clone(), &self.signer);
        self.store.write_primary(&blob);
        self.current = pending;
        self.generation = gen;
        true
    }

    /// Promote the booted (PRIMARY) selection to the rollback floor (SECONDARY)
    /// — "the trial is over, this is now the floor". Builds + signs a blob from
    /// `current` at the *current* generation and writes it to SECONDARY.
    pub fn commit(&mut self) {
        let blob = SelectorBlob::signed(self.generation, self.current.clone(), &self.signer);
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
            &self.signer,
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

    /// Whether the node is in a trial: the booted selection (PRIMARY) differs
    /// from the committed floor (SECONDARY).
    pub fn is_trial(&self) -> bool {
        self.current != self.committed
    }

    /// The generation of the currently-booted (PRIMARY) selection.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mgr() -> SystemBankManager<InMemorySelectorStore, TestSigner> {
        SystemBankManager::load(InMemorySelectorStore::new(), TestSigner)
    }

    #[test]
    fn stage_then_seal_writes_primary_only_and_enters_trial() {
        let store = InMemorySelectorStore::new();
        let mut m = SystemBankManager::load(store.clone(), TestSigner);

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
        let mut m = SystemBankManager::load(store.clone(), TestSigner);

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
        let mut m = SystemBankManager::load(store.clone(), TestSigner);

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
            let mut m = SystemBankManager::load(store.clone(), TestSigner);
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
        let m2 = SystemBankManager::load(store.clone(), TestSigner);
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
            sha256: SelectorBlob::compute_sha256(generation, &selectors),
            signature: Vec::new(), // invalid under TestSigner
        };
        store.write_primary(&bad);

        let m = SystemBankManager::load(store.clone(), TestSigner);
        // Rejected => treated as absent => empty maps, generation 0.
        assert_eq!(m.active_bank(BankSet::Vm1), None);
        assert_eq!(m.generation(), 0);

        // Also reject a blob with a tampered digest (sig over a different sha).
        let tampered = SelectorBlob {
            generation,
            selectors: selectors.clone(),
            sha256: [0u8; 32], // doesn't match contents
            signature: TestSigner.sign(&[0u8; 32]),
        };
        store.write_primary(&tampered);
        let m2 = SystemBankManager::load(store, TestSigner);
        assert_eq!(m2.active_bank(BankSet::Vm1), None);
    }

    #[test]
    fn stub_seams_are_loud_and_nonfatal() {
        // The production stubs must not panic and must behave as "empty,
        // accept-all": load yields empty/gen-0, seal no-ops to a None read.
        let mut m = SystemBankManager::load(StubSelectorStore, StubSigner);
        assert_eq!(m.generation(), 0);
        assert_eq!(m.active_bank(BankSet::Vm1), None);
        assert!(!m.seal(), "nothing staged => seal is a no-op");

        m.stage(BankSet::Vm1, Bank::B);
        assert!(m.seal()); // writes are dropped by the stub, but in-mem state advances
        assert_eq!(m.active_bank(BankSet::Vm1), Some(Bank::B));
        assert_eq!(m.generation(), 1);
    }
}
