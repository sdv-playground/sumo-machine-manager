//! Boot-vector STORAGE primitives — the signed, generation-counted boot
//! vector plus its persistence + attestation seams.
//!
//! These are the **lower-level** pieces of the node's single boot selector:
//! the on-medium record ([`SelectorBlob`]), the store contract
//! ([`SelectorStore`] + its stub / in-memory / file impls) and the attestation
//! seam ([`Signer`] + its stub / test impls). They live here, in `nv-store`, so
//! a lower crate (e.g. `vm-boot`) can read the selector without depending **up**
//! on `machine-mgr`.
//!
//! The transition engine that drives these primitives — `SystemBankManager`
//! (stage/seal/commit/rollback) and the read-only `BootSelector` view — stays in
//! `machine-mgr::system_bank_state`, which re-exports everything here so the
//! existing `machine_mgr::system_bank_state::*` import surface is unchanged.
//!
//! # Backends
//!
//! [`FileSelectorStore`] (human-inspectable JSON files) is today's backend: the
//! [`RecordSelectorStore`](crate::boot_record::RecordSelectorStore) over a file
//! record. A host store is the same adapter over its own boot-stage record
//! ([`BootRecord`](crate::boot_record::BootRecord)); the [`SelectorStore`] trait
//! stays the single swap point. `StubSelectorStore` / `StubSigner` are the loud no-op default
//! for builds that wire no store; `InMemorySelectorStore` / `TestSigner` (gated
//! behind `test-seams`) back the unit tests, and `contract` (same gate) is the
//! executable contract every store must pass. The transition engine
//! (`machine_mgr::system_bank_state::SystemBankManager`) is the load-bearing
//! boot / VM-launch authority — see its module docs.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::types::{Bank, BankSet};

/// The reference store, defined with the record adapter it is built from.
pub use crate::boot_record::FileSelectorStore;

/// One slot's entry in the **legacy slot map** ([`SelectorBlob::selectors`]):
/// the object `{"bank":"A"}` a boot stage that still reads the previous shape
/// looks up per slot. Not covered by the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotSelect {
    /// The booted bank for this slot.
    pub bank: Bank,
}

impl SlotSelect {
    /// The selection of `bank`.
    pub fn new(bank: Bank) -> Self {
        Self { bank }
    }
}

/// One image sealed into a component's bank: its size and SHA-256, as the
/// install recorded them. The sha256 is serialized as a lowercase hex string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageEntry {
    /// Sealed size in bytes.
    pub size: u64,
    /// SHA-256 of the sealed image.
    #[serde(with = "hex_array")]
    pub sha256: [u8; 32],
}

/// One component's boot selection: the bank it boots from and what was sealed
/// into that bank, keyed by part name. `images` may be empty (a bank whose
/// sealed facts are unknown, e.g. one reseeded from NV).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentEntry {
    /// The booted bank for this component.
    pub bank: Bank,
    /// Part name -> sealed image, canonically ordered.
    pub images: BTreeMap<String, ImageEntry>,
}

impl ComponentEntry {
    /// The selection of `bank` with the given sealed `images`.
    pub fn new(bank: Bank, images: BTreeMap<String, ImageEntry>) -> Self {
        Self { bank, images }
    }
}

/// The stored form of a node boot id: the first 16 bytes of SHA-256 over its
/// UTF-8 bytes. A stored all-zero digest means "unknown" / "none", not a real
/// boot id.
pub fn boot_id_digest(id: &str) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let full: [u8; 32] = Sha256::digest(id.as_bytes()).into();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// How a node transaction ended, as recorded in the [`Transaction`] header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Committed,
    RolledBack,
}

/// Why a node transaction ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// A verdict from the caller.
    Verdict,
    /// The node rolled itself back after the host-configured number of boots
    /// while armed without a verdict.
    TrialBootLimit,
    /// The primary was restored to the committed copy outside the node's
    /// verdict path — the boot stage's rollback. Recorded by the manager at
    /// load from a header left above the primary.
    BootStage,
}

/// The recorded end of a node transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resolution {
    pub outcome: Outcome,
    pub reason: Reason,
}

/// The transaction header: what the node observed about the transaction at
/// the primary generation, kept by the store apart from both copies (see
/// [`SelectorStore`]). Meaningful only while the node is in trial (PRIMARY
/// entries differ from the backup's) or when it carries a [`Resolution`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// [`boot_id_digest`] of the node boot id at arming. All-zero ⇒ unknown.
    #[serde(with = "hex_array")]
    pub armed_boot_id: [u8; 16],
    /// Distinct node boots counted while armed without a verdict.
    pub trial_boots: u8,
    /// [`boot_id_digest`] of the last boot counted. All-zero ⇒ none counted.
    #[serde(with = "hex_array")]
    pub counted_boot_id: [u8; 16],
    /// How the transaction ended, once it has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<Resolution>,
}

/// The on-medium boot vector: which bank each component boots from and what
/// was sealed into it, at a given global generation, signed.
///
/// JSON (one key per line in [`FileSelectorStore`]):
///
/// ```json
/// {
///   "generation": 3,
///   "entries": {
///     "<component id>": {
///       "bank": "B",
///       "images": { "<part name>": { "size": 4096, "sha256": "<hex>" } }
///     }
///   },
///   "sha256": "<hex>",
///   "signature": "<hex>"
/// }
/// ```
///
/// plus an optional `"transaction"` header (see [`Transaction`]; the
/// [`FileSelectorStore`] writes it only into its `transaction` file) and an
/// optional `"selectors"` legacy slot map (see [`Self::selectors`]).
///
/// # Canonical bytes
///
/// [`Self::sha256`] is the SHA-256 of (all integers little-endian):
///
/// ```text
/// u64 generation
/// for each (id, entry) in entries, ascending id:
///     u16 id.len(), id bytes, u8 bank (A = 0, B = 1), u16 images.len()
///     for each (name, image) in entry.images, ascending name:
///         u16 name.len(), name bytes, u64 size, 32 bytes sha256
/// only when a transaction header is present:
///     u8 0x01, 16 bytes armed_boot_id, u8 trial_boots, 16 bytes counted_boot_id,
///     u8 resolution (0 none, 1 committed, 2 rolled_back),
///     u8 reason (0 verdict, 1 trial_boot_limit, 2 boot_stage; 0 when no resolution)
/// ```
///
/// A blob without a header digests exactly as before the header existed.
/// Both maps are [`BTreeMap`]s precisely so this encoding is **stable**
/// regardless of insertion order. The signature is over [`Self::sha256`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectorBlob {
    /// Global anti-rollback generation. Monotonic on `seal`.
    pub generation: u64,
    /// Component id -> boot selection, canonically ordered. Covered by the
    /// signature (see [`Self::canonical_bytes`]).
    pub entries: BTreeMap<String, ComponentEntry>,
    /// The transaction header, covered by the signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<Transaction>,
    /// SHA-256 over the canonical `(generation, entries, transaction)` bytes — the digest
    /// the signature covers. Serialized as a lowercase hex string.
    #[serde(with = "hex_array")]
    pub sha256: [u8; 32],
    /// Detached signature over [`Self::sha256`] (HSM `Signer::sign`).
    /// Serialized as a lowercase hex string (empty -> `""`).
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
    /// Legacy slot map, `slot -> {bank}`, derived from `entries` by a
    /// [`FileSelectorStore`] configured with
    /// [`with_legacy_slot_map`](FileSelectorStore::with_legacy_slot_map). Never
    /// part of the digest and never consulted on read; absent unless configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selectors: Option<BTreeMap<BankSet, SlotSelect>>,
}

impl SelectorBlob {
    /// Build the canonical, order-stable byte encoding of `(generation,
    /// entries, transaction)` that [`Self::sha256`] digests and the signature
    /// covers — layout in the [type docs](Self).
    pub fn canonical_bytes(
        generation: u64,
        entries: &BTreeMap<String, ComponentEntry>,
        transaction: Option<&Transaction>,
    ) -> Vec<u8> {
        fn put_str(buf: &mut Vec<u8>, s: &str) {
            buf.extend_from_slice(&(s.len() as u16).to_le_bytes());
            buf.extend_from_slice(s.as_bytes());
        }
        let mut buf = Vec::new();
        buf.extend_from_slice(&generation.to_le_bytes());
        for (id, entry) in entries {
            put_str(&mut buf, id);
            buf.push(entry.bank as u8);
            buf.extend_from_slice(&(entry.images.len() as u16).to_le_bytes());
            for (name, img) in &entry.images {
                put_str(&mut buf, name);
                buf.extend_from_slice(&img.size.to_le_bytes());
                buf.extend_from_slice(&img.sha256);
            }
        }
        if let Some(t) = transaction {
            buf.push(0x01);
            buf.extend_from_slice(&t.armed_boot_id);
            buf.push(t.trial_boots);
            buf.extend_from_slice(&t.counted_boot_id);
            let (outcome, reason) = match t.resolution {
                None => (0, 0),
                Some(r) => (
                    match r.outcome {
                        Outcome::Committed => 1,
                        Outcome::RolledBack => 2,
                    },
                    match r.reason {
                        Reason::Verdict => 0,
                        Reason::TrialBootLimit => 1,
                        Reason::BootStage => 2,
                    },
                ),
            };
            buf.push(outcome);
            buf.push(reason);
        }
        buf
    }

    /// Compute the canonical SHA-256 for `(generation, entries, transaction)`.
    pub fn compute_sha256(
        generation: u64,
        entries: &BTreeMap<String, ComponentEntry>,
        transaction: Option<&Transaction>,
    ) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(Self::canonical_bytes(generation, entries, transaction)).into()
    }

    /// Build + sign a blob for `entries` (and `transaction`) at `generation`
    /// using `signer`.
    pub fn signed(
        generation: u64,
        entries: BTreeMap<String, ComponentEntry>,
        transaction: Option<Transaction>,
        signer: &dyn Signer,
    ) -> SelectorBlob {
        let sha256 = Self::compute_sha256(generation, &entries, transaction.as_ref());
        let signature = signer.sign(&sha256);
        SelectorBlob {
            generation,
            entries,
            transaction,
            sha256,
            signature,
            selectors: None,
        }
    }

    /// Verify both the embedded digest (recompute over the contents) and the
    /// signature over that digest. A blob whose `sha256` doesn't match its own
    /// contents, or whose signature doesn't verify, is rejected. The legacy
    /// slot map plays no part.
    pub fn is_valid(&self, signer: &dyn Signer) -> bool {
        let recomputed =
            Self::compute_sha256(self.generation, &self.entries, self.transaction.as_ref());
        recomputed == self.sha256 && signer.verify(&self.sha256, &self.signature)
    }
}

// ---------------------------------------------------------------------------
// serde helpers — hex-encode the digest + signature so the on-disk JSON blob
// is human-readable (a hex string) rather than a JSON array of bytes. Purely
// the on-disk container; the signed canonical bytes are unaffected.
// ---------------------------------------------------------------------------

mod hex_array {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer, const N: usize>(
        bytes: &[u8; N],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom(format!("expected {N} bytes")))
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Seams: storage + signing
// ---------------------------------------------------------------------------

/// What boots: the component entries at a generation, as the store issued and
/// authenticated them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootVector {
    /// The generation the store issued for these entries.
    pub generation: u64,
    /// Component id -> boot selection, canonically ordered.
    pub entries: BTreeMap<String, ComponentEntry>,
}

/// A [`SelectorStore`] write that did not land. The store must not be treated
/// as written.
#[derive(Debug)]
pub enum SelectorError {
    Io(std::io::Error),
    Serialize(String),
    /// A rollback found nothing to restore: no committed copy, or the primary
    /// already is the committed copy.
    NoTrial,
}

impl From<std::io::Error> for SelectorError {
    fn from(e: std::io::Error) -> Self {
        SelectorError::Io(e)
    }
}

impl std::fmt::Display for SelectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SelectorError::Io(e) => write!(f, "boot vector store I/O error: {e}"),
            SelectorError::Serialize(e) => write!(f, "boot vector serialize error: {e}"),
            SelectorError::NoTrial => write!(
                f,
                "nothing to roll back: the primary already is the committed copy"
            ),
        }
    }
}

impl std::error::Error for SelectorError {}

/// The boot-vector store: a PRIMARY copy (what boots), a SECONDARY copy (the
/// committed rollback floor) and the transaction header (what the node observed
/// about the transaction at the primary generation).
///
/// The store **issues the generation and authenticates its contents**; the
/// manager adopts what the store returns and never computes a generation or
/// signs anything itself. A host implements this over its own boot-stage
/// record: the boot stage may issue generations from a hardware counter and
/// have its own rollback primitive — the verbs below are exactly those
/// operations, not slot writes.
///
/// Two durability classes:
/// - the copies are "what boots" and sit under anti-rollback: only
///   [`activate`](Self::activate), [`commit`](Self::commit) and
///   [`rollback`](Self::rollback) change them;
/// - the header is "what the node observed about the transaction" and is
///   rewritten on every trial boot ([`write_transaction`](Self::write_transaction))
///   without touching either copy.
///
/// The header is tied to the primary generation it was recorded for: a header
/// whose generation differs from the primary's is stale and must be read as
/// absent (the manager does this once, at load).
///
/// Every write verb is fallible: an `Err` means the primary is unchanged, and
/// the caller must not move its in-memory view ahead of the store.
///
/// **Write order.** No failed write verb may leave a header recorded for a
/// generation *above* the primary's. So [`activate`](Self::activate) writes
/// the primary first, then the header — if the header write then fails, the
/// store logs the header loss and still returns `Ok`: the vector is the truth,
/// and trial-boot counting for that trial degrades. [`rollback`](Self::rollback)
/// writes the header first (it is for the restored, lower generation), then
/// the primary — a failed primary write leaves a header below the primary,
/// stale and ignored. Consequence: a header whose generation is above the
/// primary's, on a committed vector (primary = secondary), can only mean the
/// boot stage restored the secondary while the node was down.
pub trait SelectorStore: Send + Sync {
    /// Authenticated contents of the primary copy, or `None` (absent or failed
    /// check).
    fn read_primary(&self) -> Option<BootVector>;
    /// Authenticated contents of the secondary copy, or `None` (absent or
    /// failed check).
    fn read_secondary(&self) -> Option<BootVector>;
    /// Make `entries` the primary at a generation the store issues, strictly
    /// above both copies, and record `header` as that generation's
    /// transaction. Returns the generation. The secondary is untouched.
    ///
    /// The primary is written before the header; a header write that fails
    /// after the primary landed is logged and the call still returns `Ok`.
    /// On `Err` the primary is unchanged.
    fn activate(
        &self,
        entries: &BTreeMap<String, ComponentEntry>,
        header: &Transaction,
    ) -> Result<u64, SelectorError>;
    /// secondary := primary (same generation) — "the trial is over, this is
    /// now the floor". Idempotent; `Ok` and a no-op without a primary.
    fn commit(&self) -> Result<(), SelectorError>;
    /// primary := secondary, record `header` against the restored generation,
    /// and return that generation. The header is written before the primary.
    ///
    /// `Err(NoTrial)` when there is nothing to restore (no secondary, or
    /// the primary already is the secondary); on `Err` the primary is
    /// unchanged.
    ///
    /// A rollback restores an equal or lower generation to the primary, so a
    /// boot stage's anti-rollback check must gate on the secondary's
    /// generation, not on the primary's being monotonic.
    fn rollback(&self, header: &Transaction) -> Result<u64, SelectorError>;
    /// The transaction header and the generation it was recorded for, or
    /// `None` when there is none (or it fails the store's check).
    fn read_transaction(&self) -> Option<(u64, Transaction)>;
    /// Rewrite the header for `generation` without touching either copy.
    fn write_transaction(&self, generation: u64, header: &Transaction)
        -> Result<(), SelectorError>;
}

/// The generation a store issues on `activate`: strictly above both copies
/// (an absent copy counts as 0).
pub(crate) fn next_generation(primary: Option<&BootVector>, secondary: Option<&BootVector>) -> u64 {
    let gen = |v: Option<&BootVector>| v.map_or(0, |v| v.generation);
    gen(primary).max(gen(secondary)) + 1
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

const STUB_STORE_WARNING: &str =
    "TODO(bootloader): SystemBankState sector I/O unimplemented — selector partition layout pending bootloader support";

/// Production [`SelectorStore`] placeholder. Every method warns loudly and
/// stores nothing: reads return `None`; `commit` / `write_transaction` report
/// `Ok(())`, `activate` reports generation 1 and `rollback` generation 0 — a
/// loud no-op for builds that wire no store. **Non-fatal on purpose**, so a node
/// with only the stub wired keeps booting via `NvBootState`.
#[derive(Debug, Default, Clone)]
pub struct StubSelectorStore;

impl SelectorStore for StubSelectorStore {
    fn read_primary(&self) -> Option<BootVector> {
        tracing::warn!("{STUB_STORE_WARNING}");
        None
    }
    fn read_secondary(&self) -> Option<BootVector> {
        tracing::warn!("{STUB_STORE_WARNING}");
        None
    }
    fn activate(
        &self,
        _entries: &BTreeMap<String, ComponentEntry>,
        _header: &Transaction,
    ) -> Result<u64, SelectorError> {
        tracing::warn!("{STUB_STORE_WARNING}");
        Ok(1)
    }
    fn commit(&self) -> Result<(), SelectorError> {
        tracing::warn!("{STUB_STORE_WARNING}");
        Ok(())
    }
    fn rollback(&self, _header: &Transaction) -> Result<u64, SelectorError> {
        tracing::warn!("{STUB_STORE_WARNING}");
        Ok(0)
    }
    fn read_transaction(&self) -> Option<(u64, Transaction)> {
        tracing::warn!("{STUB_STORE_WARNING}");
        None
    }
    fn write_transaction(
        &self,
        _generation: u64,
        _header: &Transaction,
    ) -> Result<(), SelectorError> {
        tracing::warn!("{STUB_STORE_WARNING}");
        Ok(())
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
// In-memory test seams — real cells + deterministic sign/verify.
// Gated behind the `test-seams` feature so production builds never link them;
// test builds enable the feature via a [dev-dependencies] re-declaration.
// ---------------------------------------------------------------------------

/// In-memory [`SelectorStore`]: the two copies and the header in three cells
/// behind mutexes, with the file store's generation rule. Lets the
/// `SystemBankManager` be exercised end-to-end (including the reboot-mid-stage
/// case: drop the manager, `load` a fresh one from the *same* store) without
/// any hardware. Clones share the cells. [`Self::set_fail_writes`] makes every
/// write verb fail and change nothing; [`Self::set_next_generation`] makes the
/// next `activate` issue a chosen generation; [`Self::boot_stage_rollback`]
/// models the boot stage restoring the secondary.
#[cfg(feature = "test-seams")]
#[derive(Debug, Default, Clone)]
pub struct InMemorySelectorStore {
    primary: std::sync::Arc<std::sync::Mutex<Option<BootVector>>>,
    secondary: std::sync::Arc<std::sync::Mutex<Option<BootVector>>>,
    transaction: std::sync::Arc<std::sync::Mutex<Option<(u64, Transaction)>>>,
    next_generation: std::sync::Arc<std::sync::Mutex<Option<u64>>>,
    fail_writes: std::sync::Arc<std::sync::atomic::AtomicBool>,
    writes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(feature = "test-seams")]
impl InMemorySelectorStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// While `fail` is set, every write verb returns `Err` and changes nothing.
    pub fn set_fail_writes(&self, fail: bool) {
        self.fail_writes
            .store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    /// Number of write verbs that succeeded (failed ones are not counted).
    pub fn write_count(&self) -> usize {
        self.writes.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Make the next successful `activate` issue exactly `generation`; later
    /// ones follow the usual rule again.
    pub fn set_next_generation(&self, generation: u64) {
        *self.next_generation.lock().expect("generation poisoned") = Some(generation);
    }

    /// What the boot stage does when the node fails to start: primary :=
    /// secondary, header untouched. Not a contract verb — it models an actor
    /// outside the contract, so it ignores [`Self::set_fail_writes`] and is
    /// not counted in [`Self::write_count`].
    pub fn boot_stage_rollback(&self) {
        let secondary = self.read_secondary();
        *self.primary.lock().expect("primary poisoned") = secondary;
    }

    /// `Err` while writes are set to fail.
    fn check_writable(&self) -> Result<(), SelectorError> {
        if self.fail_writes.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(SelectorError::Io(std::io::Error::other(
                "injected boot vector store write failure",
            )));
        }
        Ok(())
    }

    fn count_write(&self) {
        self.writes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(feature = "test-seams")]
impl SelectorStore for InMemorySelectorStore {
    fn read_primary(&self) -> Option<BootVector> {
        self.primary.lock().expect("primary poisoned").clone()
    }
    fn read_secondary(&self) -> Option<BootVector> {
        self.secondary.lock().expect("secondary poisoned").clone()
    }
    fn activate(
        &self,
        entries: &BTreeMap<String, ComponentEntry>,
        header: &Transaction,
    ) -> Result<u64, SelectorError> {
        self.check_writable()?;
        let generation = self
            .next_generation
            .lock()
            .expect("generation poisoned")
            .take()
            .unwrap_or_else(|| {
                next_generation(self.read_primary().as_ref(), self.read_secondary().as_ref())
            });
        *self.primary.lock().expect("primary poisoned") = Some(BootVector {
            generation,
            entries: entries.clone(),
        });
        *self.transaction.lock().expect("transaction poisoned") =
            Some((generation, header.clone()));
        self.count_write();
        Ok(generation)
    }
    fn commit(&self) -> Result<(), SelectorError> {
        self.check_writable()?;
        if let Some(primary) = self.read_primary() {
            *self.secondary.lock().expect("secondary poisoned") = Some(primary);
        }
        self.count_write();
        Ok(())
    }
    fn rollback(&self, header: &Transaction) -> Result<u64, SelectorError> {
        self.check_writable()?;
        let secondary = self
            .read_secondary()
            .filter(|s| self.read_primary().as_ref() != Some(s))
            .ok_or(SelectorError::NoTrial)?;
        *self.transaction.lock().expect("transaction poisoned") =
            Some((secondary.generation, header.clone()));
        let generation = secondary.generation;
        *self.primary.lock().expect("primary poisoned") = Some(secondary);
        self.count_write();
        Ok(generation)
    }
    fn read_transaction(&self) -> Option<(u64, Transaction)> {
        self.transaction
            .lock()
            .expect("transaction poisoned")
            .clone()
    }
    fn write_transaction(
        &self,
        generation: u64,
        header: &Transaction,
    ) -> Result<(), SelectorError> {
        self.check_writable()?;
        *self.transaction.lock().expect("transaction poisoned") =
            Some((generation, header.clone()));
        self.count_write();
        Ok(())
    }
}

/// Deterministic test [`Signer`]: the "signature" is the digest with every byte
/// XOR-ed by `0xA5`. `verify` recomputes and compares — so a tampered digest or
/// a forged signature is actually rejected, which is what the
/// tampered-copy tests rely on.
#[cfg(feature = "test-seams")]
#[derive(Debug, Default, Clone)]
pub struct TestSigner;

#[cfg(feature = "test-seams")]
impl TestSigner {
    fn transform(sha: &[u8; 32]) -> Vec<u8> {
        sha.iter().map(|b| b ^ 0xA5).collect()
    }
}

#[cfg(feature = "test-seams")]
impl Signer for TestSigner {
    fn sign(&self, sha: &[u8; 32]) -> Vec<u8> {
        Self::transform(sha)
    }
    fn verify(&self, sha: &[u8; 32], sig: &[u8]) -> bool {
        sig == Self::transform(sha).as_slice()
    }
}

// ---------------------------------------------------------------------------
// The contract suite — the same contract for every implementation
// ---------------------------------------------------------------------------

/// The executable contracts. Every [`SelectorStore`] — the reference file
/// store, the in-memory seam, a host's store over its boot-stage record — must
/// pass [`exercise`](contract::exercise); every
/// [`BootRecord`](crate::boot_record::BootRecord) must pass
/// [`exercise_record`](contract::exercise_record).
#[cfg(feature = "test-seams")]
pub mod contract {
    use super::*;
    use crate::boot_record::{BootRecord, RecordCopy};

    fn header(trial_boots: u8) -> Transaction {
        Transaction {
            armed_boot_id: boot_id_digest("contract-armed"),
            trial_boots,
            counted_boot_id: [0; 16],
            resolution: None,
        }
    }

    fn entries(list: &[(&str, Bank)]) -> BTreeMap<String, ComponentEntry> {
        list.iter()
            .map(|(id, bank)| (id.to_string(), ComponentEntry::new(*bank, BTreeMap::new())))
            .collect()
    }

    /// Drive `record` through activate / commit / rollback and assert the
    /// [`BootRecord`] contract. Asserts only relative facts, so it may run
    /// against a record that starts non-empty. Panics on the first violation.
    pub fn exercise_record(record: &dyn BootRecord) {
        let e1 = entries(&[("os", Bank::A)]);
        let e2 = entries(&[("os", Bank::B)]);
        let gen = |v: Option<BootVector>| v.map_or(0, |v| v.generation);

        // activate issues a generation strictly above both copies.
        let floor =
            gen(record.read(RecordCopy::Primary)).max(gen(record.read(RecordCopy::Secondary)));
        let g1 = record.activate(&e1).expect("activate e1");
        assert!(
            g1 > floor,
            "activate issues above both copies: {g1} > {floor}"
        );
        assert_eq!(
            record.read(RecordCopy::Primary),
            Some(BootVector {
                generation: g1,
                entries: e1.clone()
            })
        );
        let g2 = record.activate(&e2).expect("activate e2");
        assert!(g2 > g1, "a second activate issues higher: {g2} > {g1}");

        // commit makes the copies equal, idempotently.
        record.commit().expect("commit");
        let primary = record.read(RecordCopy::Primary);
        assert_eq!(record.read(RecordCopy::Secondary), primary);
        record.commit().expect("second commit");
        assert_eq!(record.read(RecordCopy::Secondary), primary);
        assert_eq!(record.read(RecordCopy::Primary), primary);

        // rollback restores the secondary's generation and entries.
        let g3 = record.activate(&e1).expect("activate e1 again");
        assert!(g3 > g2, "activate over a committed floor: {g3} > {g2}");
        assert_eq!(record.rollback().expect("rollback"), g2);
        assert_eq!(record.read(RecordCopy::Primary), primary);

        // Nothing left to restore.
        assert!(record.rollback().is_err(), "rollback without a trial");
        assert_eq!(record.read(RecordCopy::Primary), primary);
    }

    /// Drive `store` through activate / commit / write_transaction / rollback
    /// and assert the contract. Asserts only relative facts, so it may run
    /// against a store that starts non-empty. Panics on the first violation.
    pub fn exercise(store: &dyn SelectorStore) {
        let (h1, h2, h3, h4, h5) = (header(1), header(2), header(3), header(4), header(5));
        let e1 = entries(&[("os", Bank::A)]);
        let e2 = entries(&[("os", Bank::B), ("vm1", Bank::A)]);
        let e3 = entries(&[("os", Bank::A), ("vm1", Bank::B)]);
        let gen = |v: Option<BootVector>| v.map_or(0, |v| v.generation);

        // activate issues a generation strictly above both copies.
        let floor = gen(store.read_primary()).max(gen(store.read_secondary()));
        let g1 = store.activate(&e1, &h1).expect("activate e1");
        assert!(
            g1 > floor,
            "activate issues above both copies: {g1} > {floor}"
        );
        assert_eq!(
            store.read_primary(),
            Some(BootVector {
                generation: g1,
                entries: e1
            })
        );
        assert_eq!(store.read_transaction(), Some((g1, h1)));

        let g2 = store.activate(&e2, &h2).expect("activate e2");
        assert!(g2 > g1, "a second activate issues higher: {g2} > {g1}");

        // commit copies the primary to the secondary, idempotently.
        store.commit().expect("commit");
        let primary = store.read_primary();
        assert_eq!(store.read_secondary(), primary);
        store.commit().expect("second commit");
        assert_eq!(store.read_secondary(), primary);
        assert_eq!(store.read_primary(), primary);

        // write_transaction changes the header and neither copy.
        store.write_transaction(g2, &h3).expect("write_transaction");
        assert_eq!(store.read_transaction(), Some((g2, h3)));
        assert_eq!(store.read_primary(), primary);
        assert_eq!(store.read_secondary(), primary);

        // rollback restores the secondary and records the header at it.
        let g3 = store.activate(&e3, &h4).expect("activate e3");
        assert!(g3 > g2, "activate over a committed floor: {g3} > {g2}");
        assert_eq!(store.rollback(&h5).expect("rollback"), g2);
        assert_eq!(store.read_primary(), store.read_secondary());
        assert_eq!(store.read_primary(), primary);
        assert_eq!(store.read_transaction(), Some((g2, h5.clone())));

        // Nothing left to restore.
        assert!(store.rollback(&h5).is_err(), "rollback without a trial");
        assert_eq!(store.read_primary(), primary);
    }
}

// ---------------------------------------------------------------------------
// File names — the reference file record and the record adapter's side files
// ---------------------------------------------------------------------------

pub(crate) const PRIMARY: &str = "primary";
pub(crate) const SECONDARY: &str = "secondary";
pub(crate) const TRANSACTION: &str = "transaction";
pub(crate) const ROWS: &str = "rows";
pub(crate) const COMMITTED: &str = "committed";

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "test-seams")]
    fn entries(id: &str, bank: Bank) -> BTreeMap<String, ComponentEntry> {
        BTreeMap::from([(id.to_string(), ComponentEntry::new(bank, BTreeMap::new()))])
    }

    fn header() -> Transaction {
        Transaction {
            armed_boot_id: [0; 16],
            trial_boots: 0,
            counted_boot_id: [0; 16],
            resolution: None,
        }
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn contract_holds_for_the_in_memory_store() {
        contract::exercise(&InMemorySelectorStore::new());
    }

    #[test]
    fn slot_json_with_legacy_enabled_key_still_parses() {
        // A slot written with the retired `enabled` key still parses (unknown
        // keys are ignored); its blob then fails `is_valid`, not the parse.
        let json = serde_json::json!({ "bank": "A", "enabled": false });
        let sel: SlotSelect = serde_json::from_value(json).expect("slot parses");
        assert_eq!(sel, SlotSelect { bank: Bank::A });
    }

    #[test]
    fn boot_stage_reason_is_byte_two_in_the_canonical_bytes() {
        let mut t = header();
        t.resolution = Some(Resolution {
            outcome: Outcome::RolledBack,
            reason: Reason::BootStage,
        });
        let bytes = SelectorBlob::canonical_bytes(1, &BTreeMap::new(), Some(&t));
        assert_eq!(bytes[bytes.len() - 2..], [2, 2], "rolled_back, boot_stage");
        assert_eq!(
            serde_json::to_value(Reason::BootStage).unwrap(),
            serde_json::json!("boot_stage")
        );
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn rollback_without_a_trial_is_no_trial() {
        let store = InMemorySelectorStore::new();
        assert!(matches!(
            store.rollback(&header()),
            Err(SelectorError::NoTrial)
        ));

        store.activate(&entries("os", Bank::A), &header()).unwrap();
        store.commit().unwrap();
        let (primary, secondary) = (store.read_primary(), store.read_secondary());
        assert!(matches!(
            store.rollback(&header()),
            Err(SelectorError::NoTrial)
        ));
        assert_eq!(store.read_primary(), primary);
        assert_eq!(store.read_secondary(), secondary);
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn in_memory_set_next_generation_is_used_once() {
        let store = InMemorySelectorStore::new();
        store.set_next_generation(42);
        assert_eq!(
            store.activate(&entries("os", Bank::A), &header()).unwrap(),
            42
        );
        assert_eq!(
            store.activate(&entries("os", Bank::B), &header()).unwrap(),
            43
        );
    }
}
