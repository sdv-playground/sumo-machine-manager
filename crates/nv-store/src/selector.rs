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
//! # Backends: JSON now, sectors/C later
//!
//! [`FileSelectorStore`] (two human-inspectable JSON slots) is today's backend;
//! the [`SelectorStore`] trait is the single swap point for a future raw
//! eMMC-sector / `libbmft` impl (the out-of-tree bootloader reads the same
//! signed record). `StubSelectorStore` / `StubSigner` are the loud no-op default
//! for builds that wire no store; `InMemorySelectorStore` / `TestSigner` (gated
//! behind `test-seams`) back the unit tests. The transition engine
//! ([`machine_mgr::system_bank_state::SystemBankManager`]) is the load-bearing
//! boot / VM-launch authority — see its module docs.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::types::{Bank, BankSet};

/// One slot's boot selection: which bank, and whether the node may boot/launch
/// it. `enabled == false` is the disable state — it **replaces** the old
/// separate top-level `disabled` set, so enable/disable now lives per slot,
/// alongside the bank, and is covered by the same signature (see
/// [`SelectorBlob::canonical_bytes`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotSelect {
    /// The booted bank for this slot.
    pub bank: Bank,
    /// Whether the node may boot/launch this slot. `#[serde(default)]` to `true`
    /// so a selection with no explicit `enabled` key (or a pre-fold on-disk blob)
    /// reads as enabled — a slot with a selection is bootable unless disabled.
    #[serde(default = "enabled_default")]
    pub enabled: bool,
}

/// `serde` default for [`SlotSelect::enabled`] — a slot is enabled unless told
/// otherwise.
fn enabled_default() -> bool {
    true
}

impl SlotSelect {
    /// A newly-selected, enabled slot.
    pub fn enabled(bank: Bank) -> Self {
        Self {
            bank,
            enabled: true,
        }
    }
}

/// The on-medium selector record: which bank each component boots from, at a
/// given global generation, signed.
///
/// `selectors` is an ordered collection ([`BTreeMap`]) precisely so the
/// canonical byte encoding used for [`Self::sha256`] is **stable** regardless of
/// insertion order — a `HashMap` would hash differently run to run and the
/// signature would not reproduce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectorBlob {
    /// Global anti-rollback generation. Monotonic on `seal`.
    pub generation: u64,
    /// `BankSet -> {bank, enabled}` boot selection, canonically ordered. The
    /// per-slot `enabled` flag folds in what used to be a separate top-level
    /// `disabled` set: a slot present with `enabled == false` is the disable
    /// state. Both the bank and the enable bit are covered by the signature
    /// (see [`Self::canonical_bytes`]).
    pub selectors: BTreeMap<BankSet, SlotSelect>,
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
    /// `(BankSet.0: u8, Bank: u8, enabled: u8)` selector triple in `BTreeMap`
    /// (ascending `BankSet`) order. `BankSet` is a `u8` newtype and `Bank` is
    /// `repr(u8)`, so three bytes per slot suffice.
    ///
    /// The `enabled` byte is part of the signed encoding, so disabling a slot
    /// (flipping its bit) changes the digest and therefore the signature — the
    /// enable/disable state is attested exactly like the bank selection.
    pub fn canonical_bytes(generation: u64, selectors: &BTreeMap<BankSet, SlotSelect>) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + selectors.len() * 3);
        buf.extend_from_slice(&generation.to_le_bytes());
        for (set, sel) in selectors {
            buf.push(set.0);
            buf.push(sel.bank as u8);
            buf.push(u8::from(sel.enabled));
        }
        buf
    }

    /// Compute the canonical SHA-256 for `(generation, selectors)`.
    pub fn compute_sha256(generation: u64, selectors: &BTreeMap<BankSet, SlotSelect>) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(Self::canonical_bytes(generation, selectors)).into()
    }

    /// Build + sign a blob for `selectors` at `generation` using `signer`.
    pub fn signed(
        generation: u64,
        selectors: BTreeMap<BankSet, SlotSelect>,
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
    /// Persist PRIMARY before the caller makes it the in-memory boot choice.
    ///
    /// A selector write is on the reboot-critical path.  Returning an error is
    /// therefore essential: accepting an activation while only the in-memory
    /// mirror changed can select an old bank after an immediate hardware reset.
    fn write_primary(&self, blob: &SelectorBlob) -> std::io::Result<()>;
    fn read_secondary(&self) -> Option<SelectorBlob>;
    fn write_secondary(&self, blob: &SelectorBlob) -> std::io::Result<()>;
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
    fn write_primary(&self, _blob: &SelectorBlob) -> std::io::Result<()> {
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
    fn write_secondary(&self, _blob: &SelectorBlob) -> std::io::Result<()> {
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
/// store) without any hardware.
#[cfg(feature = "test-seams")]
#[derive(Debug, Default, Clone)]
pub struct InMemorySelectorStore {
    primary: std::sync::Arc<std::sync::Mutex<Option<SelectorBlob>>>,
    secondary: std::sync::Arc<std::sync::Mutex<Option<SelectorBlob>>>,
}

#[cfg(feature = "test-seams")]
impl InMemorySelectorStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(feature = "test-seams")]
impl SelectorStore for InMemorySelectorStore {
    fn read_primary(&self) -> Option<SelectorBlob> {
        self.primary.lock().expect("primary poisoned").clone()
    }
    fn write_primary(&self, blob: &SelectorBlob) -> std::io::Result<()> {
        *self.primary.lock().expect("primary poisoned") = Some(blob.clone());
        Ok(())
    }
    fn read_secondary(&self) -> Option<SelectorBlob> {
        self.secondary.lock().expect("secondary poisoned").clone()
    }
    fn write_secondary(&self, blob: &SelectorBlob) -> std::io::Result<()> {
        *self.secondary.lock().expect("secondary poisoned") = Some(blob.clone());
        Ok(())
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

    /// Atomically and durably write a slot: serialize into `<name>.tmp`, flush
    /// it, rename over `<name>`, then flush the renamed file.  A CVC hardware
    /// reboot can follow the second component activation immediately; without
    /// the flush the first selector write could survive while the later VM2
    /// selection was still only in cache.
    fn write_slot(&self, name: &str, blob: &SelectorBlob) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let final_path = self.dir.join(name);
        let tmp_path = self.dir.join(format!("{name}.tmp"));
        let file = std::fs::File::create(&tmp_path)?;
        serde_json::to_writer_pretty(&file, blob)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        file.sync_all()?;
        std::fs::rename(&tmp_path, &final_path)?;
        // Re-open after rename so QNX flushes both the content and metadata of
        // the name the next boot will read.
        std::fs::File::open(&final_path)?.sync_all()
    }
}

impl SelectorStore for FileSelectorStore {
    fn read_primary(&self) -> Option<SelectorBlob> {
        self.read_slot("primary")
    }
    fn write_primary(&self, blob: &SelectorBlob) -> std::io::Result<()> {
        self.write_slot("primary", blob)
    }
    fn read_secondary(&self) -> Option<SelectorBlob> {
        self.read_slot("secondary")
    }
    fn write_secondary(&self, blob: &SelectorBlob) -> std::io::Result<()> {
        self.write_slot("secondary", blob)
    }
}
