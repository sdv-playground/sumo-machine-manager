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
//! Lives in `machine-contract` so host-os-mgr, component-mgr and the host machine manager can all
//! implement it without circular deps. The implementor holds its own NV / HSM /
//! disk handles, so these signatures stay free of those crates.

use std::collections::BTreeMap;

use nv_store::selector::ImageEntry;
use nv_store::types::Bank;

use crate::ResetKind;

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
/// `x-ota-installed-manifest` data parameter and the identData DIDs.
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

/// Mirror of `hsm::ivd::IVD_DISABLED_RECORD_PATH`: the name of the
/// administrative-disable sentinel's one inventory entry. This crate may not
/// depend on `hsm` (its dep-light allowlist), so the value is repeated here;
/// component-mgr pins the two equal with a test.
pub const DISABLED_RECORD_PATH: &str = ".admin-disabled";

impl InstalledFirmware {
    /// Display/test convenience: a single entry at [`DISABLED_RECORD_PATH`]
    /// with an all-zero digest. NOT authoritative — the IVD provider's
    /// `read_installed` zero-pads a short digest to 32 bytes, so never gate on
    /// this; the gate is [`BankProvider::disabled_record`].
    pub fn is_disabled_record(&self) -> bool {
        self.files.len() == 1
            && self.files[0].name == DISABLED_RECORD_PATH
            && self.files[0].sha256 == [0u8; 32]
    }
}

/// What one bank holds, by part name: as its installed manifest records it
/// when the bank is sealed, else as its staging record does (the verified
/// parts of an update still being staged).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BankContents {
    pub bank: Bank,
    pub images: BTreeMap<String, ImageEntry>,
    /// The node boot id the bank was sealed in, as its installed manifest
    /// records it. `None` when the manifest predates the field, the node had
    /// no boot id, or there is no readable manifest.
    pub install_boot_id: Option<String>,
    /// The client's update the bank holds, when the executor was told it: as
    /// the installed manifest records it for a sealed bank, as the staging
    /// record does for an unsealed one.
    pub update_id: Option<String>,
    /// Whether `images` comes from a sealed (signed) manifest. `false` for
    /// the parts of an update still being staged.
    pub sealed: bool,
}

/// What a bank holds toward an update not yet armed, kept beside the bank so
/// a half-staged or prepared update survives a restart as facts: each part
/// the bank holds, verified against the digest it was staged under. The
/// bank's seal marks it `sealed`; activating the bank removes it. A record
/// without an `update_id` is a part cache, not a held update.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StagingRecord {
    /// Record layout version, `1`.
    pub version: u32,
    /// The client's update this staging belongs to, when the executor was
    /// told it.
    pub update_id: Option<String>,
    /// The node boot id the staging (re)started in.
    pub node_boot_id: Option<String>,
    /// Wall-clock seconds when the staging (re)started.
    pub started_unix: u64,
    /// The parts the bank holds, each verified on intake.
    pub parts: Vec<StagedPart>,
    /// The bank is sealed over exactly `parts` and not yet activated: the
    /// update is prepared. Absent (`false`) in a record written before the
    /// field existed.
    #[serde(default)]
    pub sealed: bool,
}

impl StagingRecord {
    /// The layout version this crate writes.
    pub const VERSION: u32 = 1;
}

/// One part an unsealed bank holds: its on-medium name, size and SHA-256
/// (lowercase hex).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StagedPart {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

/// Installed contents of each bank of one component, plus whether it is in a
/// trial. See [`BankProvider::banks`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentBanks {
    /// The active bank and its contents (empty `images` when it has no
    /// readable manifest).
    pub active: BankContents,
    /// The other bank, `None` for a single-bank component or when the other
    /// bank has neither a readable manifest nor a staging record.
    pub inactive: Option<BankContents>,
    /// Whether the component runs a not-yet-committed install.
    pub in_trial: bool,
    /// The newly installed content needs a node reset that has not happened
    /// yet: the component's reset kind is `RequiresEcuReset` and the active
    /// bank's `install_boot_id` is `Some` and equal to the node's current boot
    /// id (also `Some`). Anything else, including an unknown boot id on
    /// either side, is `false`.
    pub pending_reset: bool,
}

/// Errors from [`BankProvider`] operations.
#[derive(Debug)]
pub enum BankError {
    Io(std::io::Error),
    /// The bank was never flashed — no installed firmware to read.
    NotInstalled,
    /// The installed firmware exists but failed verification.
    Unverifiable(String),
    /// The payload names a part this bank does not declare. Fail-closed: a
    /// provider with a fixed part map (a raw-partition bank) refuses the name
    /// rather than staging the bytes somewhere nothing will ever read them.
    UnknownPart(String),
    /// The provider does not offer this operation (e.g. staging bytes before
    /// their part is known, on a medium whose parts are fixed devices).
    Unsupported(String),
    /// Any other kind-specific failure.
    Failed(String),
}

/// The provider's token for bytes staged by
/// [`BankProvider::open_staging_writer`] before their part is known; handed
/// back to [`BankProvider::commit_staged`] or [`BankProvider::discard_staged`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingHandle(pub String);

impl std::fmt::Display for BankError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BankError::Io(e) => write!(f, "bank I/O error: {e}"),
            BankError::NotInstalled => write!(f, "bank not installed"),
            BankError::Unverifiable(m) => write!(f, "bank firmware unverifiable: {m}"),
            BankError::UnknownPart(p) => write!(f, "part not declared for this bank: {p}"),
            BankError::Unsupported(m) => write!(f, "bank operation not supported: {m}"),
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
/// `prune_target` (keep the parts the staging record proves) →
/// `open_staging_writer` + `commit_staged`, or `open_payload_writer`, per part
/// (each noted in the staging record) → `seal` (marks the record sealed) →
/// `activate` (removes the record) → (trial reboot) → `commit` | `rollback`.
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

    /// Whether a reboot is OWED before a new install is safe: the boot selector's
    /// next-boot selection disagrees with the running bank (e.g. after a
    /// rollback-without-reboot, or a trial flip not yet booted). In that window the
    /// running bank is loopback-mounted (unwriteable) while the selector points
    /// elsewhere, so a flash target is ambiguous — the engine refuses the update
    /// until a reboot reconverges them. Default `false` (no selector concept ⇒
    /// running is always the single authority).
    fn pending_reboot(&self) -> bool {
        false
    }

    /// Ready `bank` for a fresh install — clear it / reclaim space, seed
    /// unchanged files from the active bank if the medium supports partial OTA.
    fn prepare_target(&self, bank: Bank) -> Result<(), BankError>;

    /// Ready `bank` for an install that keeps the parts named in `keep` (the
    /// staging record's parts, each re-verified by the engine): remove
    /// everything else the bank holds toward an install, and any torn staging
    /// leftovers. Default [`Self::prepare_target`] (keeps nothing).
    fn prune_target(&self, bank: Bank, keep: &[String]) -> Result<(), BankError> {
        let _ = keep;
        self.prepare_target(bank)
    }

    /// Open a sink for one payload whose part is not known yet: the engine
    /// hashes the bytes as they stream, then names the part by its digest
    /// ([`Self::commit_staged`]) or drops them ([`Self::discard_staged`]).
    /// Default `Unsupported`: the engine then takes parts in manifest order
    /// through [`Self::open_payload_writer`].
    fn open_staging_writer(
        &self,
        bank: Bank,
    ) -> Result<(Box<dyn std::io::Write + Send>, StagingHandle), BankError> {
        let _ = bank;
        Err(BankError::Unsupported(
            "staging a payload before its part is known".into(),
        ))
    }

    /// Place the bytes behind `handle` into `bank` as part `name`, replacing
    /// an older part of that name; durable on `Ok`. Default `Unsupported`.
    fn commit_staged(
        &self,
        bank: Bank,
        handle: StagingHandle,
        name: &str,
    ) -> Result<(), BankError> {
        let _ = (bank, handle, name);
        Err(BankError::Unsupported("committing a staged payload".into()))
    }

    /// Drop the bytes behind `handle` (a payload that matched no part, or
    /// failed on the way in). Default no-op.
    fn discard_staged(&self, bank: Bank, handle: StagingHandle) -> Result<(), BankError> {
        let _ = (bank, handle);
        Ok(())
    }

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
    ///
    /// `required` is the part names this install's manifest DECLARES — the
    /// complete inventory the sealed bank must hold. A provider that stages
    /// into a bank dir uses it to settle each declared part Ship-or-Reuse
    /// (already streamed in, else copied from the active bank); parts outside
    /// it are never copied, since they belong to a different manifest. Empty
    /// when the install declares no payloads (CRL / disable / HSM keystore).
    fn seal(
        &self,
        bank: Bank,
        identity: FirmwareIdentity,
        gen: u64,
        required: &[String],
    ) -> Result<(), BankError>;

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

    /// Whether [`Self::write_disabled_record`] could persist a disable right
    /// now: its refusals, checked without writing anything. The engine asks
    /// BEFORE it stops the component, so a disable that cannot be recorded is
    /// refused while the component still runs, not enacted and then lost.
    /// `Err` names what is missing.
    fn can_persist_disabled_record(&self) -> Result<(), BankError>;

    /// Persist "administratively disabled" for `bank` by rewriting its signed
    /// installed-firmware record as the sentinel (one entry:
    /// [`DISABLED_RECORD_PATH`], zero digest, size 0) at `gen`, identity carried
    /// over from the record being replaced. Must persist or return `Err` —
    /// never a silent no-op: an unsigned or unsignable record leaves nothing for
    /// the start gate to read.
    fn write_disabled_record(&self, bank: Bank, gen: u64) -> Result<(), BankError>;

    /// The gen of a SIGNATURE-VERIFIED sentinel record on `bank`, else
    /// `Ok(None)`: a real inventory, a missing record and a record whose
    /// signature does not verify all read `None` (the last with a warn). `Err`
    /// only when a record exists but cannot be read/decoded.
    fn disabled_record(&self, bank: Bank) -> Result<Option<u64>, BankError>;

    /// Installed contents of each bank as recorded by the installed manifests,
    /// for status reporting. Not a verification. Default `None` (a provider
    /// that does not report bank contents).
    fn banks(&self) -> Option<ComponentBanks> {
        None
    }

    /// The staging record kept beside `bank`, `None` when there is none (or
    /// it cannot be read). Default `None` (a provider that keeps no record).
    fn staging_record(&self, _bank: Bank) -> Result<Option<StagingRecord>, BankError> {
        Ok(None)
    }

    /// Replace the staging record kept beside `bank`; `None` removes it.
    /// Durable on `Ok`. Default no-op (a provider that keeps no record).
    fn write_staging_record(
        &self,
        _bank: Bank,
        _record: Option<&StagingRecord>,
    ) -> Result<(), BankError> {
        Ok(())
    }
}
