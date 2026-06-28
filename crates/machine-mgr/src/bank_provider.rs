//! Bank provider — the per-kind A/B storage + lifecycle seam.
//!
//! Where [`crate::bank_activator::BankActivator`] abstracted only *activation*,
//! `BankProvider` owns the whole A/B story for one kind of updatable component:
//! which bank is live, how to stage firmware bytes into a bank, how to seal +
//! read back the installed result (inventory + identity), how to activate, and
//! how to persist commit / rollback.
//!
//! The generic engine (`ComponentBackend`) runs the OTA flow — SUIT validation,
//! the decrypt/decompress/hash pipeline, the flash state machine, the SOVD wire
//! — and delegates *every bank touch* through this trait. A new kind (e.g. RT
//! firmware on a raw partition) is then one impl, not a hardcode:
//!
//! - **`IvdBankProvider`** (component-mgr, the default): signed CBOR manifest in a bank
//!   dir + NV boot-state; the boot selector is the bank authority. VMs / host-os / hsm.
//! - **`RtBankProvider`** (the host machine manager): a raw partition — one sector for the
//!   bank selector, one for the SHA, `m7loader` to activate.
//!
//! Lives in `machine-mgr` so host-os-mgr, component-mgr and the host machine manager can all
//! implement it without circular deps. The implementor holds its own NV / HSM /
//! disk handles, so these signatures stay free of those crates.

use nv_store::types::Bank;

use crate::types::ResetKind;

/// Firmware SW-identity, decoupled from any single on-disk encoding: the IVD
/// CBOR carries all ten fields, a raw-partition kind may fill only a couple.
/// The engine maps the populated fields onto the UDS identData DIDs F187-F19E.
#[derive(Debug, Clone, Default)]
pub struct FirmwareIdentity {
    pub name: Option<String>,
    pub version: Option<String>,             // F189
    pub ecu_sw_number: Option<String>,       // F188
    pub supplier_sw_number: Option<String>,  // F194
    pub supplier_sw_version: Option<String>, // F195
    pub spare_part_number: Option<String>,   // F187
    pub odx_file_id: Option<String>,         // F19E
    pub system_name: Option<String>,         // F197
    pub programming_date: Option<String>,    // F199
    pub tester_serial: Option<String>,       // F198
}

/// One file / region in the installed bank inventory.
#[derive(Debug, Clone)]
pub struct InstalledFile {
    pub name: String,
    pub sha256: [u8; 32],
}

/// The verified installed firmware for a bank — what the engine serves as the
/// `x-sumo-installed-manifest` data parameter and the identData DIDs.
#[derive(Debug, Clone)]
pub struct InstalledFirmware {
    pub bank: Bank,
    pub gen: u64,
    pub files: Vec<InstalledFile>,
    pub identity: FirmwareIdentity,
    /// Device attestation over the manifest (IVD: ECDSA-P256; raw kinds: `None`).
    pub signature: Option<Vec<u8>>,
    /// The exact signed bytes for downstream re-verification (IVD: CBOR; else `None`).
    pub raw: Option<Vec<u8>>,
}

/// Errors from [`BankProvider`] operations.
#[derive(Debug)]
pub enum BankError {
    Io(std::io::Error),
    /// The bank was never flashed — no installed firmware to read.
    NotInstalled,
    /// The installed firmware exists but failed verification.
    Unverifiable(String),
    /// Any other kind-specific failure.
    Failed(String),
}

impl std::fmt::Display for BankError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BankError::Io(e) => write!(f, "bank I/O error: {e}"),
            BankError::NotInstalled => write!(f, "bank not installed"),
            BankError::Unverifiable(m) => write!(f, "bank firmware unverifiable: {m}"),
            BankError::Failed(m) => write!(f, "bank operation failed: {m}"),
        }
    }
}

impl std::error::Error for BankError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BankError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for BankError {
    fn from(e: std::io::Error) -> Self {
        BankError::Io(e)
    }
}

/// The per-kind A/B storage + lifecycle seam. One impl per kind; the engine
/// holds an `Arc<dyn BankProvider>` and routes every bank operation through it.
///
/// Lifecycle the engine drives for an install:
/// `prepare_target` → `open_payload_writer`* (one per part) → `seal` →
/// `activate` → (trial reboot) → `commit` | `rollback`.
pub trait BankProvider: Send + Sync {
    /// The bank currently booted / active.
    fn active_bank(&self) -> Bank;

    /// The bank the node's shared boot selector says to boot — the live boot
    /// authority — or `None` when no selector is wired (or it has no selection
    /// for this set). Unlike [`Self::active_bank`], this never falls back to the
    /// provider's own NV-seeded copy, so the caller can choose its OWN fallback
    /// (e.g. a fresher `running_bank` held elsewhere). Diagnostics serve the
    /// installed-manifest / identity from this when present. Default `None`
    /// (providers without a selector concept).
    fn selected_bank(&self) -> Option<Bank> {
        None
    }

    /// The bank the next install should target (A/B alternation off `active_bank`).
    fn target_bank(&self) -> Bank;

    /// Ready `bank` for a fresh install — clear it / reclaim space, seed
    /// unchanged files from the active bank if the medium supports partial OTA.
    fn prepare_target(&self, bank: Bank) -> Result<(), BankError>;

    /// Open a sink for one staged payload `name` in `bank`. The engine streams
    /// already-decrypted, hash-verified bytes; the provider decides where they
    /// land (a file in the bank dir, or a region of a raw partition).
    fn open_payload_writer(
        &self,
        bank: Bank,
        name: &str,
    ) -> Result<Box<dyn std::io::Write + Send>, BankError>;

    /// Finalize `bank` after the payloads are written: build + seal the
    /// installed-firmware record (IVD: hash the files, sign the CBOR with the
    /// `ivd-signing` key; raw kinds: write the selector/SHA sectors).
    fn seal(&self, bank: Bank, identity: FirmwareIdentity, gen: u64) -> Result<(), BankError>;

    /// Read + verify the installed firmware for `bank`. `Err(NotInstalled)` when
    /// the bank was never flashed.
    fn read_installed(&self, bank: Bank) -> Result<InstalledFirmware, BankError>;

    /// Re-read a single staged payload `name` in `bank` and confirm its content
    /// hashes to `expected_sha256` — catches on-disk corruption between the
    /// `open_payload_writer` write and finalize (the SOVD per-part verify). The
    /// provider knows where the bytes landed (a file in the bank dir for IVD, a
    /// region of a raw partition for other kinds); the engine only holds the
    /// `(bank, name)` it streamed and the digest the pipeline captured.
    fn verify_payload(
        &self,
        bank: Bank,
        name: &str,
        expected_sha256: &[u8; 32],
    ) -> Result<(), BankError>;

    /// Make `bank` the active image (symlink flip / partition-selector write /
    /// loader exec). Returns the reset needed to bring it up.
    fn activate(&self, bank: Bank) -> Result<ResetKind, BankError>;

    /// Commit the active (trial) bank to live: set committed, reset the
    /// trial-boot count, raise the anti-rollback floor.
    fn commit(&self) -> Result<(), BankError>;

    /// Roll back to the previously-committed bank.
    fn rollback(&self) -> Result<(), BankError>;

    /// Whether activating a new image needs a full node/ECU reset rather than a
    /// component-local one. (Absorbs `BankActivator::reset_kind`.)
    fn reset_kind(&self) -> ResetKind {
        ResetKind::Local
    }
}
