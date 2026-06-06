//! Boot-selector STORAGE primitives — the signed, generation-counted selector
//! blob plus its persistence + attestation seams.
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
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::types::{Bank, BankSet};

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
    /// the signature covers. Serialized as a lowercase hex string.
    #[serde(with = "hex_array")]
    pub sha256: [u8; 32],
    /// Detached signature over [`Self::sha256`] (HSM `Signer::sign`).
    /// Serialized as a lowercase hex string (empty -> `""`).
    #[serde(with = "hex_bytes")]
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
    pub fn signed(
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
    pub fn is_valid(&self, signer: &dyn Signer) -> bool {
        let recomputed = Self::compute_sha256(self.generation, &self.selectors);
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
    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("sha256 must be 32 bytes"))
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
/// `SystemBankManager` be exercised end-to-end (including the
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
// File-backed store — the host/sim stand-in for the eMMC selector sectors
// ---------------------------------------------------------------------------

/// File-backed [`SelectorStore`]: the PRIMARY / SECONDARY slots are two JSON
/// files (`dir/primary`, `dir/secondary`). This is the host/sim stand-in for
/// the eventual eMMC sector layout — JSON (not the canonical binary encoding)
/// purely so the slots are **human-inspectable** during bring-up. The selector
/// digest + signature still travel inside the blob, so verification on `load`
/// is unchanged; only the on-disk container differs from the future sectors.
///
/// Writes are atomic per slot: serialize into `<slot>.tmp`, then `rename` over
/// `<slot>` — a crash mid-write leaves the prior slot intact.
#[derive(Debug, Clone)]
pub struct FileSelectorStore {
    dir: PathBuf,
}

impl FileSelectorStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
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

    /// Atomically write a slot: serialize into `<name>.tmp`, then rename over
    /// `<name>`. Errors warn and are swallowed (the in-memory state in
    /// `SystemBankManager` is the live view; the file is the shadow).
    fn write_slot(&self, name: &str, blob: &SelectorBlob) {
        if let Err(e) = std::fs::create_dir_all(&self.dir) {
            tracing::warn!(dir = ?self.dir, error = %e, "selector dir create failed");
            return;
        }
        let final_path = self.dir.join(name);
        let tmp_path = self.dir.join(format!("{name}.tmp"));
        let file = match std::fs::File::create(&tmp_path) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(path = ?tmp_path, error = %e, "selector tmp create failed");
                return;
            }
        };
        if let Err(e) = serde_json::to_writer_pretty(file, blob) {
            tracing::warn!(path = ?tmp_path, error = %e, "selector serialize failed");
            return;
        }
        if let Err(e) = std::fs::rename(&tmp_path, &final_path) {
            tracing::warn!(from = ?tmp_path, to = ?final_path, error = %e, "selector rename failed");
        }
    }
}

impl SelectorStore for FileSelectorStore {
    fn read_primary(&self) -> Option<SelectorBlob> {
        self.read_slot("primary")
    }
    fn write_primary(&self, blob: &SelectorBlob) {
        self.write_slot("primary", blob);
    }
    fn read_secondary(&self) -> Option<SelectorBlob> {
        self.read_slot("secondary")
    }
    fn write_secondary(&self, blob: &SelectorBlob) {
        self.write_slot("secondary", blob);
    }
}
