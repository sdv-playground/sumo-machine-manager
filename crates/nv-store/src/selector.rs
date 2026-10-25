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
//! [`FileSelectorStore`] (three human-inspectable JSON files) is today's backend;
//! the [`SelectorStore`] trait is the single swap point for a host store over
//! its own boot-stage record. `StubSelectorStore` / `StubSigner` are the loud no-op default
//! for builds that wire no store; `InMemorySelectorStore` / `TestSigner` (gated
//! behind `test-seams`) back the unit tests, and `contract` (same gate) is the
//! executable contract every store must pass. The transition engine
//! (`machine_mgr::system_bank_state::SystemBankManager`) is the load-bearing
//! boot / VM-launch authority — see its module docs.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::types::{Bank, BankSet};

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
///     u8 reason (0 verdict, 1 trial_boot_limit; 0 when no resolution)
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
    /// and return that generation.
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
fn next_generation(primary: Option<&BootVector>, secondary: Option<&BootVector>) -> u64 {
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
/// next `activate` issue a chosen generation.
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
        *self.transaction.lock().expect("transaction poisoned") =
            Some((generation, header.clone()));
        *self.primary.lock().expect("primary poisoned") = Some(BootVector {
            generation,
            entries: entries.clone(),
        });
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

/// The executable [`SelectorStore`] contract. Every store — the reference file
/// store, the in-memory seam, a host's store over its boot-stage record — must
/// pass [`exercise`](contract::exercise).
#[cfg(feature = "test-seams")]
pub mod contract {
    use super::*;

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
// File-backed store — the host/sim reference store
// ---------------------------------------------------------------------------

const PRIMARY: &str = "primary";
const SECONDARY: &str = "secondary";
const TRANSACTION: &str = "transaction";

/// File-backed [`SelectorStore`], the reference store: three JSON files of
/// [`SelectorBlob`]s in `dir` — `primary`, `secondary` and `transaction`. JSON
/// (not the canonical binary encoding) purely so the files are
/// **human-inspectable** during bring-up. Each blob carries its digest +
/// signature; a blob that fails [`SelectorBlob::is_valid`] under the store's
/// [`Signer`] reads as absent.
///
/// - `primary` / `secondary`: the copies, with no transaction header.
/// - `transaction`: a blob with EMPTY entries at the primary generation it
///   belongs to, carrying the header.
///
/// The store issues `max(primary, secondary) + 1` on `activate`, and writes
/// the header BEFORE the copy in `activate` / `rollback`: a failed copy write
/// leaves a header recorded for a generation the primary does not have — stale,
/// ignored by the reader — and the primary unchanged.
///
/// Migration: a primary written by an earlier version carries the header
/// inside its own blob; [`read_transaction`](SelectorStore::read_transaction)
/// reads that when there is no valid `transaction` file, until the next header
/// write.
///
/// Writes are atomic per file: serialize into `<file>.tmp`, then `rename` over
/// `<file>` — a crash mid-write leaves the prior file intact.
#[derive(Clone)]
pub struct FileSelectorStore {
    dir: PathBuf,
    signer: std::sync::Arc<dyn Signer>,
    legacy_slot_map: Option<BTreeMap<String, BankSet>>,
}

impl std::fmt::Debug for FileSelectorStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSelectorStore")
            .field("dir", &self.dir)
            .field("legacy_slot_map", &self.legacy_slot_map)
            .finish_non_exhaustive()
    }
}

impl FileSelectorStore {
    /// A store over `dir`, signing and verifying every blob with `signer`.
    pub fn new(dir: impl Into<PathBuf>, signer: Box<dyn Signer>) -> Self {
        Self {
            dir: dir.into(),
            signer: signer.into(),
            legacy_slot_map: None,
        }
    }

    /// Also emit the legacy slot map (`selectors`, `slot -> {bank}`) on every
    /// copy write, translating each entry's component id to its slot via `map`
    /// (an id absent from `map` gets no slot). For a boot stage that still
    /// reads the previous shape; removed when no deployed boot stage needs it.
    /// Nothing reads the map back — it is outside the digest, so a tampered
    /// map changes nothing.
    pub fn with_legacy_slot_map(mut self, map: BTreeMap<String, BankSet>) -> Self {
        self.legacy_slot_map = Some(map);
        self
    }

    /// Read + parse a file, or `None` if it doesn't exist. A parse error
    /// warns and is treated as absent (the same "garbled selector → absent"
    /// posture as a failed signature).
    fn read_slot(&self, name: &str) -> Option<SelectorBlob> {
        let path = self.dir.join(name);
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(_) => return None,
        };
        match serde_json::from_reader(file) {
            Ok(blob) => Some(blob),
            Err(e) => {
                tracing::warn!(?path, error = %e, "selector slot unreadable — treating as absent");
                None
            }
        }
    }

    /// [`Self::read_slot`], keeping only a blob that verifies. A PRESENT blob
    /// that fails verification warns rather than vanishing silently: it reads
    /// as absent (an absent primary is the host's reseed-from-NV trigger), and
    /// this line is the only record of why.
    fn read_verified(&self, name: &str) -> Option<SelectorBlob> {
        self.read_slot(name).filter(|b| {
            let valid = b.is_valid(&*self.signer);
            if !valid {
                tracing::warn!(
                    generation = b.generation,
                    "boot selector {name} failed verification — treated as absent (will be reseeded)"
                );
            }
            valid
        })
    }

    fn read_copy(&self, name: &str) -> Option<BootVector> {
        self.read_verified(name).map(|b| BootVector {
            generation: b.generation,
            entries: b.entries,
        })
    }

    /// Sign + write a copy (no header), with the legacy slot map if configured.
    fn write_copy(
        &self,
        name: &str,
        generation: u64,
        entries: BTreeMap<String, ComponentEntry>,
    ) -> Result<(), SelectorError> {
        let mut blob = SelectorBlob::signed(generation, entries, None, &*self.signer);
        blob.selectors = self.legacy_slot_map.as_ref().map(|map| {
            blob.entries
                .iter()
                .filter_map(|(id, e)| map.get(id).map(|&set| (set, SlotSelect::new(e.bank))))
                .collect()
        });
        self.write_slot(name, &blob)
    }

    /// Sign + write the header for `generation` (empty entries).
    fn write_header(&self, generation: u64, header: &Transaction) -> Result<(), SelectorError> {
        let blob = SelectorBlob::signed(
            generation,
            BTreeMap::new(),
            Some(header.clone()),
            &*self.signer,
        );
        self.write_slot(TRANSACTION, &blob)
    }

    /// Atomically + durably write a file: serialize into `<name>.tmp`, **fsync
    /// it**, rename over `<name>`, then fsync the renamed file. The first
    /// failing step is returned as `Err`; the caller must not treat the file as
    /// written (a failure before the rename leaves the prior file intact).
    ///
    /// The fsyncs matter because a hardware reboot can follow a bank activation
    /// IMMEDIATELY, and the reboot path is kernel-direct — without the flush a
    /// just-sealed selection could sit only in the block cache and be lost
    /// across the reset, so the next boot reads the STALE (pre-seal) file.
    /// (`reboot_now` also `sync()`s globally, but flushing here makes each
    /// write durable on its own, independent of that path.)
    fn write_slot(&self, name: &str, blob: &SelectorBlob) -> Result<(), SelectorError> {
        std::fs::create_dir_all(&self.dir)?;
        let final_path = self.dir.join(name);
        let tmp_path = self.dir.join(format!("{name}.tmp"));
        let file = std::fs::File::create(&tmp_path)?;
        serde_json::to_writer_pretty(&file, blob)
            .map_err(|e| SelectorError::Serialize(e.to_string()))?;
        // Flush the payload to disk BEFORE the rename — the rename is only
        // atomic for ordering, not durability.
        file.sync_all()?;
        std::fs::rename(&tmp_path, &final_path)?;
        // Re-open + fsync the renamed file so the directory entry the next boot
        // reads is itself durable, not just the tmp payload.
        std::fs::File::open(&final_path)?.sync_all()?;
        Ok(())
    }
}

impl SelectorStore for FileSelectorStore {
    fn read_primary(&self) -> Option<BootVector> {
        self.read_copy(PRIMARY)
    }
    fn read_secondary(&self) -> Option<BootVector> {
        self.read_copy(SECONDARY)
    }
    fn activate(
        &self,
        entries: &BTreeMap<String, ComponentEntry>,
        header: &Transaction,
    ) -> Result<u64, SelectorError> {
        let generation =
            next_generation(self.read_primary().as_ref(), self.read_secondary().as_ref());
        self.write_header(generation, header)?;
        self.write_copy(PRIMARY, generation, entries.clone())?;
        Ok(generation)
    }
    fn commit(&self) -> Result<(), SelectorError> {
        match self.read_primary() {
            Some(p) => self.write_copy(SECONDARY, p.generation, p.entries),
            None => Ok(()),
        }
    }
    fn rollback(&self, header: &Transaction) -> Result<u64, SelectorError> {
        let secondary = self
            .read_secondary()
            .filter(|s| self.read_primary().as_ref() != Some(s))
            .ok_or(SelectorError::NoTrial)?;
        self.write_header(secondary.generation, header)?;
        self.write_copy(PRIMARY, secondary.generation, secondary.entries)?;
        Ok(secondary.generation)
    }
    fn read_transaction(&self) -> Option<(u64, Transaction)> {
        let blob = self
            .read_verified(TRANSACTION)
            .filter(|b| b.transaction.is_some())
            .or_else(|| self.read_verified(PRIMARY))?;
        Some((blob.generation, blob.transaction?))
    }
    fn write_transaction(
        &self,
        generation: u64,
        header: &Transaction,
    ) -> Result<(), SelectorError> {
        self.write_header(generation, header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unique per-run path under the system temp dir so concurrent test
    /// binaries don't collide.
    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sumo-selector-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

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

    /// Plant `blob` as the file `name` in `dir`, bypassing the store.
    #[cfg(feature = "test-seams")]
    fn plant(dir: &std::path::Path, name: &str, blob: &SelectorBlob) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(name), serde_json::to_vec_pretty(blob).unwrap()).unwrap();
    }

    #[test]
    fn file_store_write_into_uncreatable_dir_is_err() {
        // A regular file sits where the store directory should be, so
        // `create_dir_all` (and every later step) cannot succeed.
        let file = temp_path("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        let store = FileSelectorStore::new(file.join("store"), Box::new(StubSigner));

        assert!(store.activate(&entries("os", Bank::B), &header()).is_err());
        assert!(store.write_transaction(1, &header()).is_err());
        assert_eq!(store.read_primary(), None, "failed write left no copy");

        std::fs::remove_file(&file).unwrap();
    }

    #[test]
    fn file_store_successful_write_round_trips() {
        let dir = temp_path("ok");
        let store = FileSelectorStore::new(&dir, Box::new(StubSigner));

        assert_eq!(
            store.activate(&entries("os", Bank::A), &header()).unwrap(),
            1
        );
        store.commit().expect("commit");
        assert_eq!(
            store.activate(&entries("os", Bank::B), &header()).unwrap(),
            2
        );
        let reader = FileSelectorStore::new(&dir, Box::new(StubSigner));
        assert_eq!(
            reader.read_primary(),
            Some(BootVector {
                generation: 2,
                entries: entries("os", Bank::B)
            })
        );
        assert_eq!(
            reader.read_secondary(),
            Some(BootVector {
                generation: 1,
                entries: entries("os", Bank::A)
            })
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn legacy_slot_map_only_when_configured_and_outside_the_digest() {
        let mut written = entries("os", Bank::B);
        written.insert(
            "vm1".to_string(),
            ComponentEntry::new(Bank::A, BTreeMap::new()),
        );
        let raw = |dir: &std::path::Path, name: &str| -> SelectorBlob {
            serde_json::from_slice(&std::fs::read(dir.join(name)).unwrap()).unwrap()
        };

        // Not configured: no `selectors` key in the JSON.
        let plain_dir = temp_path("plain");
        let plain = FileSelectorStore::new(&plain_dir, Box::new(StubSigner));
        plain.activate(&written, &header()).unwrap();
        let json = std::fs::read_to_string(plain_dir.join("primary")).unwrap();
        assert!(!json.contains("selectors"), "{json}");
        assert_eq!(plain.read_primary().unwrap().entries, written);

        // Configured: `slot -> {bank}` derived from the entries; an id with no
        // slot is left out. The transaction file never carries the map.
        let legacy_dir = temp_path("legacy");
        let map = BTreeMap::from([("os".to_string(), BankSet(0))]);
        let legacy =
            FileSelectorStore::new(&legacy_dir, Box::new(StubSigner)).with_legacy_slot_map(map);
        legacy.activate(&written, &header()).unwrap();
        legacy.commit().unwrap();
        let want = Some(BTreeMap::from([(BankSet(0), SlotSelect::new(Bank::B))]));
        let read = raw(&legacy_dir, "primary");
        assert_eq!(read.selectors, want);
        assert_eq!(raw(&legacy_dir, "secondary").selectors, want);
        assert_eq!(raw(&legacy_dir, "transaction").selectors, None);
        assert_eq!(read.entries, written);
        assert!(read.is_valid(&StubSigner));

        // A modified legacy map does not affect validity (the digest is
        // recomputed over the entries alone).
        let mut tampered = read;
        tampered.selectors = Some(BTreeMap::from([(BankSet(0), SlotSelect::new(Bank::A))]));
        assert!(tampered.is_valid(&StubSigner));

        std::fs::remove_dir_all(&plain_dir).unwrap();
        std::fs::remove_dir_all(&legacy_dir).unwrap();
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn contract_holds_for_the_file_store() {
        let dir = temp_path("contract");
        contract::exercise(&FileSelectorStore::new(&dir, Box::new(TestSigner)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn contract_holds_for_the_in_memory_store() {
        contract::exercise(&InMemorySelectorStore::new());
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn tampered_copy_reads_as_absent() {
        let dir = temp_path("tampered");
        let store = FileSelectorStore::new(&dir, Box::new(TestSigner));

        // A copy whose signature doesn't verify under TestSigner (empty sig —
        // StubSigner would have produced this).
        let entries = entries("vm1", Bank::B);
        let generation = 9;
        let bad = SelectorBlob {
            generation,
            entries: entries.clone(),
            transaction: None,
            sha256: SelectorBlob::compute_sha256(generation, &entries, None),
            signature: Vec::new(), // invalid under TestSigner
            selectors: None,
        };
        plant(&dir, PRIMARY, &bad);
        plant(&dir, SECONDARY, &bad);
        assert_eq!(store.read_primary(), None);
        assert_eq!(store.read_secondary(), None);

        // Also reject a copy with a tampered digest (sig over a different sha).
        let tampered = SelectorBlob {
            generation,
            entries,
            transaction: None,
            sha256: [0u8; 32], // doesn't match contents
            signature: TestSigner.sign(&[0u8; 32]),
            selectors: None,
        };
        plant(&dir, PRIMARY, &tampered);
        assert_eq!(store.read_primary(), None);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    // --- blobs signed over the retired per-slot encoding ---

    #[cfg(feature = "test-seams")]
    #[test]
    fn legacy_slot_blob_reads_as_absent() {
        // A blob correctly signed over the OLD encoding — `[set, bank]` per
        // slot, the selection carried only in the slot map — no longer
        // verifies: the digest is over the entries, and there are none. Both
        // copies read as absent, so the node looks unseeded and the host
        // reseeds it from NV.
        use crate::types::slots;
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

        let dir = temp_path("legacy-slot");
        plant(&dir, PRIMARY, &blob);
        plant(&dir, SECONDARY, &blob);
        let store = FileSelectorStore::new(&dir, Box::new(TestSigner));
        assert_eq!(store.read_primary(), None, "PRIMARY rejected");
        assert_eq!(store.read_secondary(), None, "SECONDARY rejected");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn slot_json_with_legacy_enabled_key_still_parses() {
        // A slot written with the retired `enabled` key still parses (unknown
        // keys are ignored); its blob then fails `is_valid`, not the parse.
        let json = serde_json::json!({ "bank": "A", "enabled": false });
        let sel: SlotSelect = serde_json::from_value(json).expect("slot parses");
        assert_eq!(sel, SlotSelect { bank: Bank::A });
    }

    // --- the store contract: header, copies, generations ---

    #[cfg(feature = "test-seams")]
    #[test]
    fn activate_writes_the_header_before_the_primary_so_a_failed_primary_leaves_a_stale_header() {
        let dir = temp_path("header-first");
        let store = FileSelectorStore::new(&dir, Box::new(TestSigner));
        assert_eq!(
            store.activate(&entries("os", Bank::A), &header()).unwrap(),
            1
        );
        store.commit().unwrap();
        let before = store.read_primary().unwrap();
        let primary_bytes = std::fs::read(dir.join(PRIMARY)).unwrap();

        // Fault injection: a directory at `primary.tmp` makes
        // `File::create` fail in `write_slot` for the primary only; the
        // header goes through `transaction.tmp`, which is unaffected.
        std::fs::create_dir(dir.join("primary.tmp")).unwrap();
        let mut armed = header();
        armed.trial_boots = 1;
        assert!(
            store.activate(&entries("os", Bank::B), &armed).is_err(),
            "the primary write fails"
        );

        assert_eq!(store.read_primary(), Some(before), "primary unchanged");
        assert_eq!(
            std::fs::read(dir.join(PRIMARY)).unwrap(),
            primary_bytes,
            "primary bytes unchanged"
        );
        assert_eq!(
            store.read_transaction(),
            Some((2, armed)),
            "the header was written for a generation the primary does not have"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(feature = "test-seams")]
    #[test]
    fn v0_1_14_primary_with_an_embedded_header_reads_as_the_transaction() {
        let dir = temp_path("v0-1-14");
        let store = FileSelectorStore::new(&dir, Box::new(TestSigner));
        let e = entries("os", Bank::B);
        let mut embedded = header();
        embedded.trial_boots = 3;
        let blob = SelectorBlob::signed(7, e.clone(), Some(embedded.clone()), &TestSigner);
        plant(&dir, PRIMARY, &blob);

        let vector = BootVector {
            generation: 7,
            entries: e.clone(),
        };
        assert_eq!(store.read_primary(), Some(vector.clone()));
        assert_eq!(store.read_transaction(), Some((7, embedded)));

        // A transaction file, once written, wins over the embedded header.
        let mut other = header();
        other.trial_boots = 9;
        store.write_transaction(7, &other).unwrap();
        assert_eq!(store.read_transaction(), Some((7, other)));
        assert_eq!(store.read_primary(), Some(vector));

        // A tampered signature: neither the vector nor the header is trusted.
        let dir2 = temp_path("v0-1-14-bad");
        let store2 = FileSelectorStore::new(&dir2, Box::new(TestSigner));
        let mut bad = blob;
        bad.signature = vec![0xFF; 32];
        plant(&dir2, PRIMARY, &bad);
        assert_eq!(store2.read_primary(), None);
        assert_eq!(store2.read_transaction(), None);

        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&dir2).unwrap();
    }

    #[test]
    fn transaction_file_is_not_written_into_the_copies() {
        let dir = temp_path("header-file");
        let store = FileSelectorStore::new(&dir, Box::new(StubSigner));
        let raw = |name: &str| -> SelectorBlob {
            serde_json::from_slice(&std::fs::read(dir.join(name)).unwrap()).unwrap()
        };

        let generation = store.activate(&entries("os", Bank::A), &header()).unwrap();
        store.commit().unwrap();
        let mut counted = header();
        counted.trial_boots = 2;
        store.write_transaction(generation, &counted).unwrap();

        assert!(
            raw(PRIMARY).transaction.is_none(),
            "primary carries no header"
        );
        assert!(
            raw(SECONDARY).transaction.is_none(),
            "secondary carries no header"
        );
        let t = raw(TRANSACTION);
        assert!(t.entries.is_empty(), "the header file carries no entries");
        assert_eq!(t.transaction, Some(counted));
        assert_eq!(t.generation, raw(PRIMARY).generation);

        std::fs::remove_dir_all(&dir).unwrap();
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
