//! Integrity Verification Data (IVD) — bank-self-signing for secure boot.
//!
//! After OTA staging completes (the bank dir contains the validated
//! payloads but the bank pointer hasn't flipped yet), the HSM signs
//! the bank contents with its device-local `ivd-signing` key. The
//! signature lives in the bank dir itself — `ivd-manifest.cbor` +
//! `ivd-signature.bin` — so rollback automatically discards the sig
//! along with the bank, and a trial flip just exposes the staged
//! bank with its existing signature intact.
//!
//! External secure boot (or the `sumo-verify` CLI for managed-cvc
//! deployments without one) reads the manifest + signature before
//! launching the component:
//!
//! 1. Read `ivd-manifest.cbor` and `ivd-signature.bin`.
//! 2. Verify the signature over the manifest bytes using the HSM's
//!    `ivd-signing` public half (fetched once via
//!    `get_public_key_der("ivd-signing")` and cached).
//! 3. Re-hash every file listed in the manifest and compare.
//! 4. Refuse to launch if any check fails.
//!
//! # Wire shape
//!
//! `ivd-manifest.cbor` is a single CBOR map:
//!
//! ```text
//! IvdManifest = {
//!   0: uint,           ; ivd_version (currently 1)
//!   1: tstr,           ; bank_id    (component-defined, e.g. "vm2/bank_a")
//!   2: uint,           ; signed_at_unix
//!   3: [* FileEntry],
//! }
//!
//! FileEntry = {
//!   0: tstr,           ; relative_path (POSIX, '/' separator)
//!   1: bstr,           ; sha256 of file contents (32 bytes)
//!   2: uint,           ; size in bytes
//! }
//! ```
//!
//! `ivd-signature.bin` is the raw DER-encoded ECDSA-SHA256 signature
//! produced by the HSM's `HsmCryptoProvider::sign` over the CBOR
//! bytes of `ivd-manifest.cbor`. No COSE wrapping — the verifier
//! handles raw DER directly via the same `sign`/`verify` ops.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{HsmError, HsmProvider};

/// Slot key_id used by `hsm.sign(...)` / `hsm.verify(...)`. Mirrors
/// `KeyRole::IvdSigning.key_id()`.
pub const IVD_KEY_ID: &str = "ivd-signing";

/// Manifest version. Bumped if the CBOR shape changes.
///
/// - v1: bank_id + file inventory only.
/// - v2: adds `gen` (install-time generation counter) for run-time
///   anti-rollback. v1 manifests on existing banks will fail to
///   deserialize after this bump — devices must be re-flashed.
pub const IVD_MANIFEST_VERSION: u64 = 2;

/// Filenames the IVD machinery owns inside a bank dir.
pub const IVD_MANIFEST_FILE: &str = "ivd-manifest.cbor";
pub const IVD_SIGNATURE_FILE: &str = "ivd-signature.bin";

/// IVD manifest — what the HSM signs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IvdManifest {
    #[serde(rename = "0")]
    pub ivd_version: u64,

    /// Unix seconds at sign time. Informational — verifiers use
    /// `gen`, not timestamps, for rollback policy.
    #[serde(rename = "2")]
    pub signed_at_unix: u64,

    /// Bank file inventory, sorted by `relative_path` for determinism.
    #[serde(rename = "3")]
    pub files: Vec<IvdFile>,

    /// Install-time generation counter. Monotonic per-device per
    /// bank set, assigned at OTA install as
    /// `nv.committed_gen + 1` (where committed_gen is the
    /// currently-committed bank's stored gen).
    ///
    /// Two run-time invariants verifiers check:
    /// 1. `manifest.gen >= committed_gen` — refuses rollback below
    ///    whatever was last successfully committed.
    /// 2. `manifest.gen == NV.bank_install_gen[this_slot]` —
    ///    catches "files swapped between slots" mid-trial. The NV
    ///    record was written at install time and the attacker
    ///    can't manufacture a matching HSM signature.
    #[serde(rename = "4")]
    pub gen: u64,
}

/// One file in the bank inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IvdFile {
    /// POSIX-style relative path under the bank dir. Slash separator,
    /// no leading slash, no `..` components.
    #[serde(rename = "0")]
    pub relative_path: String,

    /// SHA-256 of the file contents.
    #[serde(rename = "1", with = "serde_bytes")]
    pub sha256: Vec<u8>,

    #[serde(rename = "2")]
    pub size: u64,
}

/// Anything that can go wrong specifically inside the IVD machinery.
/// Mostly wraps `HsmError` and IO; verification failures get their
/// own variants for orchestrator-visible reasons.
#[derive(Debug)]
pub enum IvdError {
    Io(std::io::Error, PathBuf),
    Cbor(String),
    /// Manifest's claim about a file's hash doesn't match what's on disk.
    HashMismatch {
        path: String,
        claimed: Vec<u8>,
        actual: Vec<u8>,
    },
    /// Manifest's claim about a file's size doesn't match what's on disk.
    SizeMismatch {
        path: String,
        claimed: u64,
        actual: u64,
    },
    /// A file listed in the manifest isn't on disk.
    MissingFile(String),
    /// A file is on disk that the manifest doesn't claim.
    UnexpectedFile(String),
    /// Manifest's `gen` doesn't match the per-bank install_gen
    /// recorded in NV — typically a between-slot swap during trial.
    GenMismatch { expected: u64, claimed: u64 },
    /// Manifest's `gen` is below the committed_gen floor — rollback
    /// attempt below a successfully-committed bank.
    GenBelowFloor { manifest: u64, floor: u64 },
    /// HSM rejected the verify or signature is bad.
    SignatureInvalid,
    /// Manifest carries a version this build doesn't understand.
    UnsupportedManifestVersion(u64),
    Hsm(HsmError),
}

impl std::fmt::Display for IvdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IvdError::Io(e, p) => write!(f, "ivd io {}: {e}", p.display()),
            IvdError::Cbor(s) => write!(f, "ivd cbor: {s}"),
            IvdError::HashMismatch { path, .. } => write!(f, "ivd hash mismatch: {path}"),
            IvdError::SizeMismatch { path, claimed, actual } => {
                write!(f, "ivd size mismatch {path}: manifest says {claimed}, on disk {actual}")
            }
            IvdError::MissingFile(p) => write!(f, "ivd missing file: {p}"),
            IvdError::UnexpectedFile(p) => write!(f, "ivd unexpected file (not in manifest): {p}"),
            IvdError::GenMismatch { expected, claimed } => {
                write!(f, "ivd gen mismatch: NV expected {expected}, manifest claims {claimed}")
            }
            IvdError::GenBelowFloor { manifest, floor } => {
                write!(f, "ivd gen below floor: manifest {manifest} < committed_gen {floor}")
            }
            IvdError::SignatureInvalid => write!(f, "ivd signature invalid"),
            IvdError::UnsupportedManifestVersion(v) => {
                write!(f, "ivd manifest version {v} not supported")
            }
            IvdError::Hsm(e) => write!(f, "ivd hsm: {e}"),
        }
    }
}

impl std::error::Error for IvdError {}

impl From<HsmError> for IvdError {
    fn from(e: HsmError) -> Self {
        IvdError::Hsm(e)
    }
}

/// Walk `bank_dir` and produce a sorted file inventory. Skips the
/// IVD-owned files themselves (manifest + signature) so they don't
/// shadow themselves. Does not recurse into symlinks.
pub fn build_manifest(bank_dir: &Path, gen: u64) -> Result<IvdManifest, IvdError> {
    let mut files = Vec::new();
    collect_files(bank_dir, bank_dir, &mut files)?;
    Ok(build_manifest_from_files(files, gen))
}

/// Construct a manifest from a pre-computed file inventory.
///
/// The OTA streaming pipeline already SHA-256s each payload as it
/// writes it (and verifies against the OEM-signed SUIT digest); the
/// resulting `(path, size, hash)` triples are exactly what the IVD
/// manifest needs. Skipping the re-walk + re-hash here saves the full
/// rootfs SHA pass — ~2.5 s for an 80 MB rootfs on the CVC.
///
/// The function sorts the input by `relative_path` so the signed CBOR
/// is deterministic regardless of payload-arrival order.
pub fn build_manifest_from_files(mut files: Vec<IvdFile>, gen: u64) -> IvdManifest {
    files.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

    let signed_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    IvdManifest {
        ivd_version: IVD_MANIFEST_VERSION,
        signed_at_unix,
        files,
        gen,
    }
}

fn collect_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<IvdFile>,
) -> Result<(), IvdError> {
    let entries =
        fs::read_dir(dir).map_err(|e| IvdError::Io(e, dir.to_path_buf()))?;
    for entry in entries {
        let entry = entry.map_err(|e| IvdError::Io(e, dir.to_path_buf()))?;
        let path = entry.path();
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();

        // Skip the IVD-owned files when scanning the bank — the
        // manifest must not enumerate itself or the signature.
        if dir == root
            && (file_name == IVD_MANIFEST_FILE || file_name == IVD_SIGNATURE_FILE)
        {
            continue;
        }

        let meta = entry
            .metadata()
            .map_err(|e| IvdError::Io(e, path.clone()))?;

        if meta.file_type().is_dir() {
            collect_files(root, &path, out)?;
            continue;
        }
        if !meta.file_type().is_file() {
            // Skip symlinks, sockets, etc. The OTA pipeline doesn't
            // produce them today; rejecting them outright keeps the
            // attack surface small.
            continue;
        }

        let relative = path
            .strip_prefix(root)
            .map_err(|e| IvdError::Cbor(format!("strip_prefix: {e}")))?;
        let relative_path = relative
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");

        let bytes = fs::read(&path).map_err(|e| IvdError::Io(e, path.clone()))?;
        let sha256 = sha256(&bytes);
        out.push(IvdFile {
            relative_path,
            sha256,
            size: bytes.len() as u64,
        });
    }
    Ok(())
}

/// CBOR-encode the manifest. The bytes returned here are exactly
/// what gets signed (and exactly what gets written to
/// `ivd-manifest.cbor`).
pub fn encode_manifest(manifest: &IvdManifest) -> Result<Vec<u8>, IvdError> {
    let mut buf = Vec::new();
    ciborium::into_writer(manifest, &mut buf)
        .map_err(|e| IvdError::Cbor(format!("encode: {e}")))?;
    Ok(buf)
}

/// CBOR-decode a manifest from bytes (e.g. read from
/// `ivd-manifest.cbor`). Rejects unsupported versions.
pub fn decode_manifest(bytes: &[u8]) -> Result<IvdManifest, IvdError> {
    let manifest: IvdManifest = ciborium::from_reader(bytes)
        .map_err(|e| IvdError::Cbor(format!("decode: {e}")))?;
    if manifest.ivd_version != IVD_MANIFEST_VERSION {
        return Err(IvdError::UnsupportedManifestVersion(manifest.ivd_version));
    }
    Ok(manifest)
}

/// Build the manifest, sign it with the HSM's IVD signing key, and
/// write both artefacts into `bank_dir`. Idempotent at the file
/// level — if called twice the previous artefacts get overwritten.
///
/// `gen` is the install-time generation counter — the caller assigns
/// it as `nv.committed_gen + 1` and writes the same value into
/// `NV.bank_install_gen[target_slot]` so the verify-time cross-check
/// can pin "the manifest in this slot is the one we installed here".
///
/// This variant walks `bank_dir` and hashes every file from scratch.
/// Use `sign_bank_with_files` when the caller already has a verified
/// file inventory (e.g. from the OTA streaming pipeline, which hashes
/// each payload as it writes).
///
/// Returns the manifest that was signed (informational; the file on
/// disk is the source of truth for verifiers).
#[cfg(feature = "crypto")]
pub fn sign_bank(
    hsm: &dyn HsmProvider,
    bank_dir: &Path,
    gen: u64,
) -> Result<IvdManifest, IvdError> {
    let hash_start = std::time::Instant::now();
    let mut files = Vec::new();
    collect_files(bank_dir, bank_dir, &mut files)?;
    let hash_ms = hash_start.elapsed().as_millis() as u64;
    sign_bank_with_files(hsm, bank_dir, gen, files, Some(hash_ms))
}

/// Sign a bank using a pre-computed file inventory.
///
/// The OTA streaming pipeline already SHA-256s each payload while
/// writing it to disk and verifies the digest against the OEM-signed
/// SUIT manifest. Those `(relative_path, size, sha256)` triples are
/// exactly what the IVD manifest needs — re-walking the bank dir and
/// re-hashing is duplicate work (~2.5 s for the 80 MB rootfs on the
/// CVC).
///
/// Trust chain: SUIT envelope (OEM-signed) authenticates the
/// `image_digest` of each payload. The streaming pipeline computes
/// the hash and compares; on match, the bytes that landed on disk
/// match the OEM's claim. We then attest to those same bytes here
/// with the device's `ivd-signing` key — no re-read necessary. If
/// the disk later disagrees with what we signed, launch-time verify
/// catches it (same as any post-flash tamper).
///
/// `walk_hash_ms` is an optional timing breakdown for the caller's
/// dir-walk step (None when files came from the streaming path with
/// effectively zero walk cost). Logged as `hash_ms=0` either way; the
/// distinction only matters to `sign_bank`.
#[cfg(feature = "crypto")]
pub fn sign_bank_with_files(
    hsm: &dyn HsmProvider,
    bank_dir: &Path,
    gen: u64,
    files: Vec<IvdFile>,
    walk_hash_ms: Option<u64>,
) -> Result<IvdManifest, IvdError> {
    let started = std::time::Instant::now();

    let manifest = build_manifest_from_files(files, gen);
    let manifest_bytes = encode_manifest(&manifest)?;
    let hash_ms = walk_hash_ms.unwrap_or(0);

    let sig_start = std::time::Instant::now();
    let sig = hsm.sign(IVD_KEY_ID, &manifest_bytes)?;
    let sig_ms = sig_start.elapsed().as_millis() as u64;

    fs::write(bank_dir.join(IVD_MANIFEST_FILE), &manifest_bytes)
        .map_err(|e| IvdError::Io(e, bank_dir.join(IVD_MANIFEST_FILE)))?;
    fs::write(bank_dir.join(IVD_SIGNATURE_FILE), &sig)
        .map_err(|e| IvdError::Io(e, bank_dir.join(IVD_SIGNATURE_FILE)))?;

    let total_bytes: u64 = manifest.files.iter().map(|f| f.size).sum();
    tracing::info!(
        bank_dir = %bank_dir.display(),
        gen = manifest.gen,
        files = manifest.files.len(),
        total_bytes,
        hash_ms,
        sig_ms,
        total_ms = started.elapsed().as_millis() as u64,
        "ivd sign OK",
    );

    Ok(manifest)
}

/// Verification pins. Both checks are optional but should both be
/// passed by the launch-time gate; only the developer
/// "did my sig round-trip" use case omits them.
#[derive(Debug, Default, Clone, Copy)]
pub struct VerifyPins {
    /// `NV.bank_install_gen[slot]` — value the device assigned when
    /// this bank was installed. Verifier requires
    /// `manifest.gen == expected_install_gen`. Catches a swap of
    /// signed-but-different-gen content into this slot during trial.
    pub expected_install_gen: Option<u64>,
    /// `NV.committed_gen` — the per-bank-set ratchet. Verifier
    /// requires `manifest.gen >= min_committed_gen`. Catches
    /// rollback below a successfully-committed bank.
    pub min_committed_gen: Option<u64>,
}

/// Read manifest + signature from `bank_dir`, verify the sig using
/// the HSM's IVD public key, then enforce the supplied [`VerifyPins`]
/// and re-hash every file the manifest claims.
#[cfg(feature = "crypto")]
pub fn verify_bank(
    hsm: &dyn HsmProvider,
    bank_dir: &Path,
    pins: VerifyPins,
) -> Result<IvdManifest, IvdError> {
    let started = std::time::Instant::now();
    let result = verify_bank_inner(hsm, bank_dir, pins, started);
    if let Err(ref e) = result {
        // Inner records its own per-phase timings on success; on the
        // pre-signature error paths (file IO etc.) we still want a
        // single failure line for the operator log.
        tracing::error!(
            bank_dir = %bank_dir.display(),
            expected_install_gen = ?pins.expected_install_gen,
            min_committed_gen = ?pins.min_committed_gen,
            total_ms = started.elapsed().as_millis() as u64,
            error = %e,
            "ivd verify FAIL",
        );
    }
    result
}

#[cfg(feature = "crypto")]
fn verify_bank_inner(
    hsm: &dyn HsmProvider,
    bank_dir: &Path,
    pins: VerifyPins,
    started: std::time::Instant,
) -> Result<IvdManifest, IvdError> {
    let manifest_path = bank_dir.join(IVD_MANIFEST_FILE);
    let signature_path = bank_dir.join(IVD_SIGNATURE_FILE);

    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|e| IvdError::Io(e, manifest_path.clone()))?;
    let sig = fs::read(&signature_path)
        .map_err(|e| IvdError::Io(e, signature_path.clone()))?;

    // ---- Phase 1: signature verification ----
    let sig_start = std::time::Instant::now();
    let ok = hsm
        .verify(IVD_KEY_ID, &manifest_bytes, &sig)
        .map_err(IvdError::Hsm)?;
    let sig_verify_ms = sig_start.elapsed().as_millis() as u64;
    if !ok {
        return Err(IvdError::SignatureInvalid);
    }

    let manifest = decode_manifest(&manifest_bytes)?;

    // Per-slot install-gen cross-check. The NV record was written
    // at install time; the manifest carries the same value baked
    // into the signed payload. A mismatch means the bank dir's
    // contents are not the ones we installed in this slot.
    if let Some(expected_gen) = pins.expected_install_gen {
        if manifest.gen != expected_gen {
            return Err(IvdError::GenMismatch {
                expected: expected_gen,
                claimed: manifest.gen,
            });
        }
    }

    // Run-floor: refuse any bank whose gen has fallen below the
    // last successfully-committed gen. The active+committed bank
    // is at `committed_gen` exactly; the trial bank is at
    // `committed_gen + 1`. Anything below `committed_gen` is a
    // rollback we don't permit.
    if let Some(floor) = pins.min_committed_gen {
        if manifest.gen < floor {
            return Err(IvdError::GenBelowFloor {
                manifest: manifest.gen,
                floor,
            });
        }
    }

    // ---- Phase 2: re-hash every file the manifest claims ----
    let hash_start = std::time::Instant::now();

    let mut on_disk = std::collections::BTreeSet::new();
    let mut probe = Vec::new();
    collect_files(bank_dir, bank_dir, &mut probe)?;
    for f in &probe {
        on_disk.insert(f.relative_path.clone());
    }

    let claimed_set: std::collections::BTreeSet<&String> =
        manifest.files.iter().map(|f| &f.relative_path).collect();

    // Detect files on disk that the manifest doesn't claim.
    for f in &on_disk {
        if !claimed_set.contains(f) {
            return Err(IvdError::UnexpectedFile(f.clone()));
        }
    }

    // Detect manifest claims with no matching file, plus per-file
    // hash/size verification.
    let claimed_map: BTreeMap<&String, &IvdFile> =
        manifest.files.iter().map(|f| (&f.relative_path, f)).collect();
    let mut total_bytes: u64 = 0;
    for claim in manifest.files.iter() {
        let path = bank_dir.join(&claim.relative_path);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(IvdError::MissingFile(claim.relative_path.clone()));
            }
            Err(e) => return Err(IvdError::Io(e, path)),
        };
        if bytes.len() as u64 != claim.size {
            return Err(IvdError::SizeMismatch {
                path: claim.relative_path.clone(),
                claimed: claim.size,
                actual: bytes.len() as u64,
            });
        }
        total_bytes += bytes.len() as u64;
        let actual = sha256(&bytes);
        if actual != claim.sha256 {
            return Err(IvdError::HashMismatch {
                path: claim.relative_path.clone(),
                claimed: claim.sha256.clone(),
                actual,
            });
        }
        // Touch the map so the unused-import lint doesn't complain
        // when we go through claimed_map for another check later.
        let _ = claimed_map.get(&claim.relative_path);
    }

    let hash_verify_ms = hash_start.elapsed().as_millis() as u64;
    let total_ms = started.elapsed().as_millis() as u64;

    tracing::info!(
        bank_dir = %bank_dir.display(),
        gen = manifest.gen,
        files = manifest.files.len(),
        total_bytes,
        sig_verify_ms,
        hash_verify_ms,
        total_ms,
        "ivd verify OK",
    );

    Ok(manifest)
}

/// SHA-256 of `bytes`. Uses `sha2` when the `crypto` feature is on;
/// falls back to a minimal panic on non-crypto builds (no HSM op
/// path needs hashing without crypto).
#[cfg(feature = "crypto")]
fn sha256(bytes: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).to_vec()
}

#[cfg(not(feature = "crypto"))]
fn sha256(_bytes: &[u8]) -> Vec<u8> {
    panic!("hsm::ivd::sha256 requires the `crypto` feature")
}

#[cfg(all(test, feature = "crypto"))]
mod tests {
    use super::*;

    fn write(p: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    fn temp_bank(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("hsm-ivd-test-{}", name));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn build_manifest_lists_files_sorted_and_skips_ivd_files() {
        let bank = temp_bank("list");
        write(&bank.join("kernel"), b"kernel bytes");
        write(&bank.join("rootfs.img"), b"rootfs");
        write(&bank.join("nested/qvm.conf"), b"qvm-conf");
        // Existing IVD-owned files should be skipped.
        write(&bank.join(IVD_MANIFEST_FILE), b"stale manifest");
        write(&bank.join(IVD_SIGNATURE_FILE), b"stale sig");

        let m = build_manifest(&bank, 1).unwrap();
        let paths: Vec<&str> = m.files.iter().map(|f| f.relative_path.as_str()).collect();
        assert_eq!(paths, vec!["kernel", "nested/qvm.conf", "rootfs.img"]);
        assert_eq!(m.files[0].size, b"kernel bytes".len() as u64);
        assert_eq!(m.gen, 1);

        let _ = std::fs::remove_dir_all(&bank);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let bank = temp_bank("roundtrip");
        write(&bank.join("a"), b"alpha");
        write(&bank.join("b"), b"beta");
        let m = build_manifest(&bank, 42).unwrap();
        let bytes = encode_manifest(&m).unwrap();
        let back = decode_manifest(&bytes).unwrap();
        assert_eq!(back.files.len(), 2);
        assert_eq!(back.gen, 42);
        let _ = std::fs::remove_dir_all(&bank);
    }

    fn provisioned_sim(name: &str) -> (crate::sim::SimHsm, PathBuf) {
        use crate::payload::*;

        let keystore = std::env::temp_dir().join(format!("hsm-ivd-keystore-{}", name));
        let _ = std::fs::remove_dir_all(&keystore);
        std::fs::create_dir_all(&keystore).unwrap();

        let hsm = crate::sim::SimHsm::new(
            PathBuf::from("/dev/null"),
            keystore.clone(),
            5100,
        );

        // Minimal v2 keystore: just `ivd-signing` as a device-
        // generated EC slot. generate_missing_local_keys produces the
        // keypair on disk.
        let ks = HsmKeystore {
            schema_version: SCHEMA_VERSION,
            security_version: 1,
            identities: vec![],
            slots: vec![KeySlot {
                key_id: IVD_KEY_ID.to_string(),
                key_kind: KEY_TYPE_EC_P256,
                anchor_public_key: None,
                allowed_guests: None,
                allowed_ops: Some(vec![OP_SIGN, OP_VERIFY, OP_GET_PUBKEY]),
            }],
        };
        hsm.write_keystore(&ks).unwrap();
        std::fs::write(keystore.join("provision_state"), b"1\n").unwrap();

        (hsm, keystore)
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let bank = temp_bank("sign-verify");
        write(&bank.join("kernel"), b"kernel bytes");
        write(&bank.join("rootfs.img"), &vec![0xAB; 4096]);
        write(&bank.join("nested/qvm.conf"), b"cmdline foo=bar");

        let (hsm, keystore) = provisioned_sim("sign-verify");
        let manifest = sign_bank(&hsm, &bank, 7).unwrap();
        assert_eq!(manifest.files.len(), 3);
        assert_eq!(manifest.gen, 7);
        assert!(bank.join(IVD_MANIFEST_FILE).exists());
        assert!(bank.join(IVD_SIGNATURE_FILE).exists());

        let pins = VerifyPins {
            expected_install_gen: Some(7),
            min_committed_gen: Some(7),
        };
        let back = verify_bank(&hsm, &bank, pins).unwrap();
        assert_eq!(back.gen, 7);

        let _ = std::fs::remove_dir_all(&bank);
        let _ = std::fs::remove_dir_all(&keystore);
    }

    #[test]
    fn verify_rejects_tampered_file() {
        let bank = temp_bank("tamper");
        // 15-byte original; tamper to a different 15-byte content so
        // SizeMismatch doesn't fire first and we exercise the hash
        // comparison specifically.
        write(&bank.join("kernel"), b"original kernel");

        let (hsm, keystore) = provisioned_sim("tamper");
        sign_bank(&hsm, &bank, 1).unwrap();

        std::fs::write(bank.join("kernel"), b"tampered kernel").unwrap();

        match verify_bank(&hsm, &bank, VerifyPins::default()) {
            Err(IvdError::HashMismatch { path, .. }) => assert_eq!(path, "kernel"),
            other => panic!("expected HashMismatch, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&bank);
        let _ = std::fs::remove_dir_all(&keystore);
    }

    #[test]
    fn verify_rejects_unexpected_extra_file() {
        let bank = temp_bank("extra");
        write(&bank.join("kernel"), b"k");

        let (hsm, keystore) = provisioned_sim("extra");
        sign_bank(&hsm, &bank, 1).unwrap();

        // Drop an extra file AFTER signing — bank shouldn't have
        // anything the manifest didn't authorize.
        std::fs::write(bank.join("evil-file"), b"unauthorised").unwrap();

        match verify_bank(&hsm, &bank, VerifyPins::default()) {
            Err(IvdError::UnexpectedFile(p)) => assert_eq!(p, "evil-file"),
            other => panic!("expected UnexpectedFile, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&bank);
        let _ = std::fs::remove_dir_all(&keystore);
    }

    #[test]
    fn verify_rejects_gen_mismatch() {
        let bank = temp_bank("genmm");
        write(&bank.join("f"), b"x");

        let (hsm, keystore) = provisioned_sim("genmm");
        sign_bank(&hsm, &bank, 5).unwrap();

        // NV says this slot should have gen=6 (e.g. someone swapped
        // a gen=5 manifest into a slot the device installed gen=6 to)
        let pins = VerifyPins {
            expected_install_gen: Some(6),
            ..Default::default()
        };
        match verify_bank(&hsm, &bank, pins) {
            Err(IvdError::GenMismatch { expected, claimed }) => {
                assert_eq!(expected, 6);
                assert_eq!(claimed, 5);
            }
            other => panic!("expected GenMismatch, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&bank);
        let _ = std::fs::remove_dir_all(&keystore);
    }

    #[test]
    fn verify_rejects_gen_below_floor() {
        let bank = temp_bank("genfloor");
        write(&bank.join("f"), b"x");

        let (hsm, keystore) = provisioned_sim("genfloor");
        // Sign at gen=3
        sign_bank(&hsm, &bank, 3).unwrap();

        // Run-floor says we've committed gen=5 elsewhere — refuse.
        let pins = VerifyPins {
            min_committed_gen: Some(5),
            ..Default::default()
        };
        match verify_bank(&hsm, &bank, pins) {
            Err(IvdError::GenBelowFloor { manifest, floor }) => {
                assert_eq!(manifest, 3);
                assert_eq!(floor, 5);
            }
            other => panic!("expected GenBelowFloor, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&bank);
        let _ = std::fs::remove_dir_all(&keystore);
    }

    #[test]
    fn verify_accepts_trial_gen_above_floor() {
        // Models the trial-mode case: committed bank at gen=5, trial
        // bank at gen=6. Floor is 5; trial bank verifies fine.
        let bank = temp_bank("trial");
        write(&bank.join("f"), b"trial-bank");

        let (hsm, keystore) = provisioned_sim("trial");
        sign_bank(&hsm, &bank, 6).unwrap();

        let pins = VerifyPins {
            expected_install_gen: Some(6),
            min_committed_gen: Some(5),
        };
        let back = verify_bank(&hsm, &bank, pins).unwrap();
        assert_eq!(back.gen, 6);

        let _ = std::fs::remove_dir_all(&bank);
        let _ = std::fs::remove_dir_all(&keystore);
    }

    /// `sign_bank_with_files` skips the dir walk. Mimics the OTA
    /// streaming path: caller computed hashes during write, passes
    /// them in; verifier later re-reads the same files and finds the
    /// hashes match.
    #[test]
    fn sign_with_precomputed_files_roundtrips() {
        let bank = temp_bank("sign-with-files");
        // Write the files on disk so verify can re-hash them later.
        write(&bank.join("kernel"), b"kernel bytes");
        write(&bank.join("rootfs.img"), b"rootfs bytes");

        // Pre-compute the same hashes the streaming pipeline would
        // emit. (In production these come from process_raw_payload's
        // [u8; 32] return; here we hash by hand.)
        let kernel_bytes = b"kernel bytes".to_vec();
        let rootfs_bytes = b"rootfs bytes".to_vec();
        let kernel_hash = sha256(&kernel_bytes);
        let rootfs_hash = sha256(&rootfs_bytes);
        // Intentionally pass un-sorted; build_manifest_from_files sorts.
        let files = vec![
            IvdFile {
                relative_path: "rootfs.img".into(),
                sha256: rootfs_hash,
                size: rootfs_bytes.len() as u64,
            },
            IvdFile {
                relative_path: "kernel".into(),
                sha256: kernel_hash,
                size: kernel_bytes.len() as u64,
            },
        ];

        let (hsm, keystore) = provisioned_sim("sign-with-files");
        let manifest = sign_bank_with_files(&hsm, &bank, 42, files, None).unwrap();
        assert_eq!(manifest.gen, 42);
        assert_eq!(manifest.files.len(), 2);
        // Sorted result.
        assert_eq!(manifest.files[0].relative_path, "kernel");
        assert_eq!(manifest.files[1].relative_path, "rootfs.img");
        assert!(bank.join(IVD_MANIFEST_FILE).exists());
        assert!(bank.join(IVD_SIGNATURE_FILE).exists());

        // Verifier re-reads from disk and checks the manifest's
        // claims — proving the streaming-derived hashes are
        // interchangeable with dir-walk-derived ones.
        let pins = VerifyPins {
            expected_install_gen: Some(42),
            min_committed_gen: Some(42),
        };
        let back = verify_bank(&hsm, &bank, pins).unwrap();
        assert_eq!(back.gen, 42);

        let _ = std::fs::remove_dir_all(&bank);
        let _ = std::fs::remove_dir_all(&keystore);
    }
}
