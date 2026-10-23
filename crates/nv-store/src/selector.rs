//! Boot-vector STORAGE primitives — the signed, generation-counted boot
//! vector plus its persistence + attestation seams.
//!
//! These are the **lower-level** pieces of the node's single boot selector:
//! the on-medium record ([`SelectorBlob`]), the two-slot persistence seam
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
//! [`FileSelectorStore`] (two human-inspectable JSON slots) is today's backend;
//! the [`SelectorStore`] trait is the single swap point for a host store (the
//! boot stage reads the same signed record). `StubSelectorStore` / `StubSigner` are the loud no-op default
//! for builds that wire no store; `InMemorySelectorStore` / `TestSigner` (gated
//! behind `test-seams`) back the unit tests. The transition engine
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

/// How a node transaction ended, as recorded in the PRIMARY copy's
/// [`Transaction`] header.
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

/// The transaction header carried by the PRIMARY copy only (the backup never
/// carries one), inside the signed digest. Meaningful only while the node is
/// in trial (PRIMARY entries differ from the backup's) or when it carries a
/// [`Resolution`].
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
/// plus an optional `"transaction"` header (PRIMARY only, see
/// [`Transaction`]) and an optional `"selectors"` legacy slot map (see
/// [`Self::selectors`]).
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
    /// The transaction header — PRIMARY only, covered by the signature.
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

/// A [`SelectorStore`] write that did not land. The slot must not be treated
/// as written.
#[derive(Debug)]
pub enum SelectorError {
    Io(std::io::Error),
    Serialize(String),
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
        }
    }
}

impl std::error::Error for SelectorError {}

/// The two-slot persistence seam for the selector partition: a PRIMARY (booted)
/// slot and a SECONDARY (rollback floor) slot.
///
/// The production impl is the host store; the test impl keeps two
/// in-memory cells. Keeping this a trait makes the manager's cache + transition
/// logic testable now and leaves the hardware edge swappable when the bootloader
/// sector contract lands.
///
/// Writes are fallible: an `Err` means the slot was not written, and the caller
/// must not move its in-memory view ahead of storage.
pub trait SelectorStore: Send + Sync {
    fn read_primary(&self) -> Option<SelectorBlob>;
    fn write_primary(&self, blob: &SelectorBlob) -> Result<(), SelectorError>;
    fn read_secondary(&self) -> Option<SelectorBlob>;
    fn write_secondary(&self, blob: &SelectorBlob) -> Result<(), SelectorError>;
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
/// nothing: reads return `None`, writes are dropped but report `Ok(())` — a
/// loud no-op for builds that wire no store. **Non-fatal on purpose** —
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
    fn write_primary(&self, _blob: &SelectorBlob) -> Result<(), SelectorError> {
        tracing::warn!(
            "TODO(bootloader): SystemBankState sector I/O unimplemented — selector partition layout pending bootloader support"
        );
        Ok(())
    }
    fn read_secondary(&self) -> Option<SelectorBlob> {
        tracing::warn!(
            "TODO(bootloader): SystemBankState sector I/O unimplemented — selector partition layout pending bootloader support"
        );
        None
    }
    fn write_secondary(&self, _blob: &SelectorBlob) -> Result<(), SelectorError> {
        tracing::warn!(
            "TODO(bootloader): SystemBankState sector I/O unimplemented — selector partition layout pending bootloader support"
        );
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
// In-memory test seams — real sectors + deterministic sign/verify.
// Gated behind the `test-seams` feature so production builds never link them;
// test builds enable the feature via a [dev-dependencies] re-declaration.
// ---------------------------------------------------------------------------

/// In-memory [`SelectorStore`]: two real cells behind a mutex. Lets the
/// `SystemBankManager` be exercised end-to-end (including the
/// reboot-mid-stage case: drop the manager, `load` a fresh one from the *same*
/// store) without any hardware. [`Self::set_fail_writes`] makes every write
/// fail (shared across clones) so callers' failure paths can be exercised.
#[cfg(feature = "test-seams")]
#[derive(Debug, Default, Clone)]
pub struct InMemorySelectorStore {
    primary: std::sync::Arc<std::sync::Mutex<Option<SelectorBlob>>>,
    secondary: std::sync::Arc<std::sync::Mutex<Option<SelectorBlob>>>,
    fail_writes: std::sync::Arc<std::sync::atomic::AtomicBool>,
    writes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(feature = "test-seams")]
impl InMemorySelectorStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// While `fail` is set, every write returns `Err` and leaves both slots
    /// untouched.
    pub fn set_fail_writes(&self, fail: bool) {
        self.fail_writes
            .store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    /// Number of writes that landed (failed writes are not counted).
    pub fn write_count(&self) -> usize {
        self.writes.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn write_slot(
        &self,
        slot: &std::sync::Mutex<Option<SelectorBlob>>,
        blob: &SelectorBlob,
    ) -> Result<(), SelectorError> {
        if self.fail_writes.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(SelectorError::Io(std::io::Error::other(
                "injected boot vector store write failure",
            )));
        }
        *slot.lock().expect("slot poisoned") = Some(blob.clone());
        self.writes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(feature = "test-seams")]
impl SelectorStore for InMemorySelectorStore {
    fn read_primary(&self) -> Option<SelectorBlob> {
        self.primary.lock().expect("primary poisoned").clone()
    }
    fn write_primary(&self, blob: &SelectorBlob) -> Result<(), SelectorError> {
        self.write_slot(&self.primary, blob)
    }
    fn read_secondary(&self) -> Option<SelectorBlob> {
        self.secondary.lock().expect("secondary poisoned").clone()
    }
    fn write_secondary(&self, blob: &SelectorBlob) -> Result<(), SelectorError> {
        self.write_slot(&self.secondary, blob)
    }
}

/// Deterministic test [`Signer`]: the "signature" is the digest with every byte
/// XOR-ed by `0xA5`. `verify` recomputes and compares — so a tampered digest or
/// a forged signature is actually rejected, which is what the
/// verify-failing-blob test relies on.
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
// File-backed store — the host/sim stand-in for the host store
// ---------------------------------------------------------------------------

/// File-backed [`SelectorStore`]: the PRIMARY / SECONDARY slots are two JSON
/// files (`dir/primary`, `dir/secondary`). This is the host/sim stand-in for
/// the host store — JSON (not the canonical binary encoding) purely so the
/// slots are **human-inspectable** during bring-up. The digest + signature
/// still travel inside the blob, so verification on `load` is unchanged.
///
/// Writes are atomic per slot: serialize into `<slot>.tmp`, then `rename` over
/// `<slot>` — a crash mid-write leaves the prior slot intact.
#[derive(Debug, Clone)]
pub struct FileSelectorStore {
    dir: PathBuf,
    legacy_slot_map: Option<BTreeMap<String, BankSet>>,
}

impl FileSelectorStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            legacy_slot_map: None,
        }
    }

    /// Also emit the legacy slot map (`selectors`, `slot -> {bank}`) on every
    /// write, translating each entry's component id to its slot via `map`
    /// (an id absent from `map` gets no slot). For a boot stage that still
    /// reads the previous shape; removed when no deployed boot stage needs it.
    /// Nothing reads the map back — it is outside the digest, so a tampered
    /// map changes nothing.
    pub fn with_legacy_slot_map(mut self, map: BTreeMap<String, BankSet>) -> Self {
        self.legacy_slot_map = Some(map);
        self
    }

    /// Read + parse a slot file, or `None` if it doesn't exist. A parse error
    /// warns and is treated as absent (the same "garbled selector → absent"
    /// posture `load` already applies to a failed signature).
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

    /// Atomically + durably write a slot: serialize into `<name>.tmp`, **fsync
    /// it**, rename over `<name>`, then fsync the renamed file. The first
    /// failing step is returned as `Err`; the caller must not treat the slot as
    /// written (a failure before the rename leaves the prior slot intact).
    ///
    /// The fsyncs matter because a hardware reboot can follow a bank activation
    /// IMMEDIATELY, and the reboot path is kernel-direct — without the flush a
    /// just-sealed selection could sit only in the block cache and be lost
    /// across the reset, so the next boot reads the STALE (pre-seal) slot.
    /// (`reboot_now` also `sync()`s globally, but flushing here makes each
    /// write durable on its own, independent of that path.)
    fn write_slot(&self, name: &str, blob: &SelectorBlob) -> Result<(), SelectorError> {
        std::fs::create_dir_all(&self.dir)?;
        let final_path = self.dir.join(name);
        let tmp_path = self.dir.join(format!("{name}.tmp"));
        let mut blob = blob.clone();
        blob.selectors = self.legacy_slot_map.as_ref().map(|map| {
            blob.entries
                .iter()
                .filter_map(|(id, e)| map.get(id).map(|&set| (set, SlotSelect::new(e.bank))))
                .collect()
        });
        let file = std::fs::File::create(&tmp_path)?;
        serde_json::to_writer_pretty(&file, &blob)
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
    fn read_primary(&self) -> Option<SelectorBlob> {
        self.read_slot("primary")
    }
    fn write_primary(&self, blob: &SelectorBlob) -> Result<(), SelectorError> {
        self.write_slot("primary", blob)
    }
    fn read_secondary(&self) -> Option<SelectorBlob> {
        self.read_slot("secondary")
    }
    fn write_secondary(&self, blob: &SelectorBlob) -> Result<(), SelectorError> {
        self.write_slot("secondary", blob)
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

    fn blob(generation: u64) -> SelectorBlob {
        let mut entries = BTreeMap::new();
        entries.insert(
            "os".to_string(),
            ComponentEntry::new(Bank::B, BTreeMap::new()),
        );
        SelectorBlob::signed(generation, entries, None, &StubSigner)
    }

    #[test]
    fn file_store_write_into_uncreatable_dir_is_err() {
        // A regular file sits where the store directory should be, so
        // `create_dir_all` (and every later step) cannot succeed.
        let file = temp_path("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        let store = FileSelectorStore::new(file.join("store"));

        assert!(store.write_primary(&blob(1)).is_err());
        assert!(store.write_secondary(&blob(1)).is_err());
        assert_eq!(store.read_primary(), None, "failed write left no slot");

        std::fs::remove_file(&file).unwrap();
    }

    #[test]
    fn file_store_successful_write_round_trips() {
        let dir = temp_path("ok");
        let store = FileSelectorStore::new(&dir);

        store.write_primary(&blob(4)).expect("primary write");
        store.write_secondary(&blob(2)).expect("secondary write");
        assert_eq!(store.read_primary(), Some(blob(4)));
        assert_eq!(store.read_secondary(), Some(blob(2)));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn legacy_slot_map_only_when_configured_and_outside_the_digest() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "os".to_string(),
            ComponentEntry::new(Bank::B, BTreeMap::new()),
        );
        entries.insert(
            "vm1".to_string(),
            ComponentEntry::new(Bank::A, BTreeMap::new()),
        );
        let written = SelectorBlob::signed(7, entries, None, &StubSigner);

        // Not configured: no `selectors` key in the JSON.
        let plain_dir = temp_path("plain");
        let plain = FileSelectorStore::new(&plain_dir);
        plain.write_primary(&written).unwrap();
        let json = std::fs::read_to_string(plain_dir.join("primary")).unwrap();
        assert!(!json.contains("selectors"), "{json}");
        assert_eq!(plain.read_primary(), Some(written.clone()));

        // Configured: `slot -> {bank}` derived from the entries; an id with no
        // slot is left out.
        let legacy_dir = temp_path("legacy");
        let map = BTreeMap::from([("os".to_string(), BankSet(0))]);
        let legacy = FileSelectorStore::new(&legacy_dir).with_legacy_slot_map(map);
        legacy.write_primary(&written).unwrap();
        let read = legacy.read_primary().unwrap();
        assert_eq!(
            read.selectors,
            Some(BTreeMap::from([(BankSet(0), SlotSelect::new(Bank::B))]))
        );
        assert_eq!(read.entries, written.entries);
        assert!(read.is_valid(&StubSigner));

        // A modified legacy map does not affect validity (the digest is
        // recomputed over the entries alone).
        let mut tampered = read;
        tampered.selectors = Some(BTreeMap::from([(BankSet(0), SlotSelect::new(Bank::A))]));
        assert!(tampered.is_valid(&StubSigner));

        std::fs::remove_dir_all(&plain_dir).unwrap();
        std::fs::remove_dir_all(&legacy_dir).unwrap();
    }
}
