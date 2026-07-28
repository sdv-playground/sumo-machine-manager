//! `IvdBankProvider` — the IVD/A-B implementation of
//! [`machine_mgr::BankProvider`] for component-mgr bank sets.
//!
//! This is the default `BankProvider`: a signed CBOR IVD manifest living in
//! a bank dir, an optional activator (IFS write / partition swap) for
//! activation, and NV boot-state + the shared boot selector for the A/B +
//! trial + commit/rollback lifecycle. It owns every *bank touch*
//! the OTA engine used to inline — `ComponentBackend` now delegates to it through an
//! `Arc<dyn BankProvider>`.
//!
//! The bodies here were **moved** out of `backend.rs` / `ota.rs` (Phase 0
//! defined the trait; Phase 1 routes the mechanics through it). The engine
//! keeps its own concerns — the flash state machine, the DID cache + identData
//! serving, HSM enrolment arming, the health probe, and session/security.
//!
//! What the provider holds is exactly the state these methods need:
//! `nv`, `bank_set`, the bank-dir layout (`images_dir` + `dir_name`),
//! `single_bank`, `hsm`, `bank_activator`, and `running_bank`. It carries no
//! engine state, so a future host-os / RT provider is a sibling impl, not a
//! fork of the engine.

use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use nv_store::block::BlockDevice;
use nv_store::store::NvStore;
use nv_store::types::{Bank, BankSet};

use machine_mgr::bank_provider::{
    BankError, BankProvider, FirmwareIdentity, InstalledFile, InstalledFirmware,
};
use machine_mgr::ResetKind;

use crate::ota;

/// The IVD/A-B [`BankProvider`]: signed CBOR manifest in a bank dir, optional
/// activator, NV boot-state + boot selector. Backs VMs, host-os and hsm bank
/// sets.
pub struct IvdBankProvider<D: BlockDevice + Send + 'static> {
    nv: Arc<Mutex<NvStore<D>>>,
    bank_set: BankSet,
    /// Whether this bank set is single-banked (HSM — always bank A, no trial).
    single_bank: bool,
    /// Root under which `<dir_name>/bank_{a,b}` live. `None` for in-memory
    /// test backends — the provider then has no on-disk bank to touch.
    images_dir: Option<PathBuf>,
    /// On-disk dir name for this set (`vm1`, `host-os`, ...), from the
    /// backend's `BankSetSpec`.
    dir_name: String,
    /// HSM provider — the provisioning authority `seal` gates on
    /// (`is_provisioned()`); IVD signing itself goes through `hsm_crypto`.
    hsm: Option<Arc<Mutex<dyn hsm::HsmProvider>>>,
    /// Crypto handle (e.g. the host's shared link-B `LinkBClient`, or a SimHsm)
    /// `seal` uses to sign the IVD manifest via `ivd::sign_bank_crypto`. Required
    /// for sealing a real bank — `seal` errors when it's `None`. The
    /// `is_provisioned()` pre-sign guard stays on `hsm`. Set via
    /// [`with_hsm_crypto`](Self::with_hsm_crypto).
    hsm_crypto: Option<Arc<dyn hsm::HsmCryptoProvider>>,
    /// Activator invoked by `activate()` (RT launcher, IFS write, ...) — runs
    /// before the boot selector is sealed so a failure leaves NV/selector
    /// pointing at the previously-active bank. `None` for VMs whose qvm/process
    /// cycle is the activation.
    bank_activator: Option<Arc<dyn machine_mgr::BankActivator>>,
    /// The bank the ECU is actually running on. Seeded from NV at construction
    /// (NV `active_bank` may differ after install — that's the *next-boot*
    /// bank). The engine keeps its own running-bank for its read paths; this
    /// copy backs only `active_bank()` / `target_bank()` as the **fallback**
    /// when no shared boot selector is injected.
    running_bank: Mutex<Bank>,
    /// The node's shared, signed boot selector — the **write** handle
    /// (`Arc<RwLock<SystemBankManager>>`). When present it is the **PRIMARY**
    /// source for `active_bank()` / `target_bank()` (`running_bank` / NV
    /// `active_bank` are the fallback) AND the OTA write path stages / seals /
    /// commits / rolls it back so it tracks the real bank. `None` for tests and
    /// the inline construction in `backend.rs` (no selector wired), which
    /// preserves the prior NV-only fallback behaviour.
    ///
    /// Held as the full `SharedSystemBankState` (not the read-only
    /// `BootSelector` view) precisely because the OTA path now mutates it:
    /// `activate`/`commit`/`rollback` take a short-lived `.write()` lock. Reads
    /// take a `.read()` lock. Behaviour-preserving by design: the selector
    /// tracks the same bank NV does (dual-write), so a populated selector
    /// yields the same bank the fallback would. A later piece removes the
    /// symlink fallback once the selector is the sole authority.
    selector: Option<machine_mgr::SharedSystemBankState>,
}

impl<D: BlockDevice + Send + 'static> IvdBankProvider<D> {
    /// Build a provider from the backend's current state. `running_bank` is
    /// seeded the same way `ComponentBackend::with_options` seeds its own copy:
    /// `Bank::A` for single-bank, else NV `active_bank`.
    ///
    /// `selector` is the node's shared boot selector **write** handle. `Some`
    /// makes it the PRIMARY source for `active_bank()` / `target_bank()` with
    /// the NV/symlink path as fallback, AND the destination the OTA path writes
    /// (`activate` seals, `commit`/`rollback` follow `ota::*`); `None` keeps
    /// today's NV/symlink-only behaviour (the inline construction in
    /// `backend.rs` and all tests pass `None`).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        nv: Arc<Mutex<NvStore<D>>>,
        bank_set: BankSet,
        single_bank: bool,
        images_dir: Option<PathBuf>,
        dir_name: String,
        hsm: Option<Arc<Mutex<dyn hsm::HsmProvider>>>,
        bank_activator: Option<Arc<dyn machine_mgr::BankActivator>>,
        selector: Option<machine_mgr::SharedSystemBankState>,
    ) -> Self {
        let running_bank = if single_bank {
            Bank::A
        } else {
            let nv_guard = nv.lock().unwrap();
            nv_guard
                .read_boot_state()
                .map(|s| s.banks[bank_set.as_index()].active_bank)
                .unwrap_or(Bank::A)
        };
        Self {
            nv,
            bank_set,
            single_bank,
            images_dir,
            dir_name,
            hsm,
            hsm_crypto: None,
            bank_activator,
            running_bank: Mutex::new(running_bank),
            selector,
        }
    }

    /// Inject the crypto handle (e.g. the host's shared link-B `LinkBClient`, or
    /// a SimHsm) [`seal`](Self::seal) signs the IVD manifest with, via
    /// `ivd::sign_bank_crypto` (its lone `sign` op over `HsmCryptoProvider`); the
    /// `is_provisioned()` pre-sign guard stays on `hsm`. Required for sealing a
    /// real bank — `seal` errors when this is unset. Threaded from
    /// `FactoryDeps::hsm_crypto` by the component factory.
    pub fn with_hsm_crypto(mut self, crypto: Arc<dyn hsm::HsmCryptoProvider>) -> Self {
        self.hsm_crypto = Some(crypto);
        self
    }

    /// Path of the target bank directory under `images_dir`. `None` when no
    /// images_dir is configured (tests / in-memory only). Exposed because the
    /// engine's streaming pipeline writes payloads to `target_bank_dir/<name>`
    /// directly (it owns the decrypt/decompress/hash stages).
    pub fn target_bank_dir(&self, target: Bank) -> Option<PathBuf> {
        self.images_dir
            .as_ref()
            .map(|images_dir| images_dir.join(&self.dir_name).join(bank_dir_name(target)))
    }

    /// The booted bank from the **fallback** source used by `active_bank()`
    /// when no boot selector is injected: the `running_bank` copy seeded from
    /// NV at construction (only changes on `ecu_reset`). Unchanged from the
    /// pre-selector behaviour.
    fn fallback_active_bank(&self) -> Bank {
        *self.running_bank.lock().expect("running_bank poisoned")
    }

    /// The booted bank from the **fallback** source used by `target_bank()`
    /// when no boot selector is injected: NV `active_bank` (the *next-boot*
    /// bank), defaulting to `Bank::A` on a missing/unreadable boot state
    /// (first-ever flash). The boot selector is the authority when injected;
    /// this NV read is purely the un-injected fallback. Single-bank is handled
    /// by the caller (always targets `Bank::A`).
    fn fallback_target_active(&self) -> Bank {
        let nv = match self.nv.lock() {
            Ok(nv) => nv,
            Err(_) => return Bank::A,
        };
        nv.read_boot_state()
            .map(|s| s.banks[self.bank_set.as_index()].active_bank)
            .unwrap_or(Bank::A)
    }

    /// Wipe the target bank dir (frees ~1 image worth of space) and remove any
    /// orphaned staged files left in `images_dir` root by previous flashes.
    /// `pub` so the engine's thin `prepare_target_bank_dir` delegator (which a
    /// couple of call sites use directly, separately from the bundled
    /// `prepare_target`) can reach it.
    pub fn prepare_target_bank_dir(&self, target: Bank) -> Result<(), BankError> {
        let Some(images_dir) = self.images_dir.as_ref() else {
            return Ok(());
        };
        let set_name = &self.dir_name;
        let bank_dir = images_dir.join(set_name).join(bank_dir_name(target));
        std::fs::create_dir_all(&bank_dir).map_err(|e| {
            BankError::Failed(format!("create bank dir {}: {e}", bank_dir.display()))
        })?;
        let mut cleared = 0usize;
        if let Ok(entries) = std::fs::read_dir(&bank_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Err(e) = std::fs::remove_file(&path) {
                        tracing::warn!("failed to clear {}: {e}", path.display());
                    } else {
                        cleared += 1;
                    }
                }
            }
        }
        tracing::info!(
            target = %bank_dir.display(),
            cleared,
            "prepared target bank dir for {set_name}"
        );

        // Wipe legacy staged files in images_dir root (pre-refactor layout).
        for suffix in &[
            "staged.img",
            "kernel-staged.img",
            "config-staged.yaml",
            "qvm-config-staged.conf",
        ] {
            let p = images_dir.join(format!("{set_name}-{suffix}"));
            if p.exists() {
                let _ = std::fs::remove_file(&p);
            }
        }
        // And any pre-refactor compressed-input scratch tmps.
        for n in 0..16 {
            let p = images_dir.join(format!("{set_name}-upload-{n}.tmp"));
            if p.exists() {
                let _ = std::fs::remove_file(&p);
            }
        }
        Ok(())
    }

    /// Copy any files in the active bank that don't already exist in the
    /// target bank, so a partial OTA ends with a complete target bank. Runs
    /// AFTER streaming finishes and BEFORE IVD signing so the signature covers
    /// the final bank contents. `pub` so the engine's `seed_target_from_active`
    /// delegator (used directly by `bank_seed_integration_tests`) can reach it;
    /// `seal` also calls it just before signing.
    pub fn seed_target_from_active(&self, target: Bank) -> Result<(), BankError> {
        if self.single_bank {
            return Ok(());
        }
        let Some(images_dir) = self.images_dir.as_ref() else {
            return Ok(());
        };

        let active = {
            let nv = self
                .nv
                .lock()
                .map_err(|_| BankError::Failed("nv lock".into()))?;
            let state = nv
                .read_boot_state()
                .ok_or_else(|| BankError::Failed("no boot state".into()))?;
            state.banks[self.bank_set.as_index()].active_bank
        };

        if active == target {
            // Defensive — target_bank is always active.other(); never self-seed.
            return Ok(());
        }

        let set_name = &self.dir_name;
        let source_dir = images_dir.join(set_name).join(bank_dir_name(active));
        let target_dir = images_dir.join(set_name).join(bank_dir_name(target));

        match crate::bank_seed::seed_missing_files(&source_dir, &target_dir) {
            Ok(seeded) if seeded.is_empty() => {
                tracing::debug!(
                    target = %target_dir.display(),
                    source = %source_dir.display(),
                    "bank seed: no files copied (full update or empty active)"
                );
                Ok(())
            }
            Ok(seeded) => {
                tracing::info!(
                    target = %target_dir.display(),
                    source = %source_dir.display(),
                    count = seeded.len(),
                    paths = ?seeded,
                    "bank seed: copied unstreamed files from active bank"
                );
                Ok(())
            }
            Err(e) => {
                tracing::error!(
                    target = %target_dir.display(),
                    source = %source_dir.display(),
                    error = %e,
                    "bank seed failed — refusing to sign/activate a partial bank"
                );
                Err(BankError::Failed(format!(
                    "bank seed from {} to {}: {e}",
                    source_dir.display(),
                    target_dir.display()
                )))
            }
        }
    }
}

/// Map the manifest's [`hsm::ivd::IvdIdentity`] onto the trait's
/// kind-agnostic [`FirmwareIdentity`]. Empty strings (the "not provided"
/// encoding in the CBOR) become `None`.
fn ivd_identity_to_firmware(id: &hsm::ivd::IvdIdentity) -> FirmwareIdentity {
    let opt = |s: &str| (!s.is_empty()).then(|| s.to_string());
    FirmwareIdentity {
        name: opt(&id.name),
        version: opt(&id.version),
        ecu_sw_number: opt(&id.ecu_sw_number),
        supplier_sw_number: opt(&id.supplier_sw_number),
        supplier_sw_version: opt(&id.supplier_sw_version),
        spare_part_number: opt(&id.spare_part_number),
        odx_file_id: opt(&id.odx_file_id),
        system_name: opt(&id.system_name),
        programming_date: opt(&id.programming_date),
        tester_serial: opt(&id.tester_serial),
    }
}

/// Inverse of [`ivd_identity_to_firmware`] for the `seal` call: the engine
/// hands a [`FirmwareIdentity`] (mapped from the SUIT `ImageMeta`), and the
/// IVD manifest stores readable CBOR text strings (`""` for absent fields).
pub(crate) fn firmware_to_ivd_identity(id: &FirmwareIdentity) -> hsm::ivd::IvdIdentity {
    let s = |o: &Option<String>| o.clone().unwrap_or_default();
    hsm::ivd::IvdIdentity {
        name: s(&id.name),
        version: s(&id.version),
        ecu_sw_number: s(&id.ecu_sw_number),
        supplier_sw_number: s(&id.supplier_sw_number),
        supplier_sw_version: s(&id.supplier_sw_version),
        spare_part_number: s(&id.spare_part_number),
        odx_file_id: s(&id.odx_file_id),
        system_name: s(&id.system_name),
        programming_date: s(&id.programming_date),
        tester_serial: s(&id.tester_serial),
    }
}

impl<D: BlockDevice + Send + 'static> BankProvider for IvdBankProvider<D> {
    fn active_bank(&self) -> Bank {
        // PRIMARY: the node's shared boot selector, when injected. FALLBACK:
        // the `running_bank` copy seeded from NV. The selector is seeded from
        // `NvBootState`, so a populated selector returns the same bank the
        // fallback would — behaviour-preserving. An absent selection for this
        // set (e.g. selector not yet seeded for it) falls through to NV too.
        self.selected_bank()
            .unwrap_or_else(|| self.fallback_active_bank())
    }

    fn selected_bank(&self) -> Option<Bank> {
        // ONLY the shared boot selector's selection for this set — no NV /
        // symlink / `running_bank` fallback. `None` when no selector is wired
        // or it has no selection for this set, letting the caller pick its own
        // fallback. This is the live boot authority the diagnostics serve path
        // (`ComponentBackend::serving_bank`) prefers.
        self.selector.as_ref().and_then(|s| {
            s.read()
                .expect("selector poisoned")
                .active_bank(self.bank_set)
        })
    }

    fn target_bank(&self) -> Bank {
        // Single-bank (HSM) always targets bank A.
        if self.single_bank {
            return Bank::A;
        }
        // Derive the active bank selector-then-fallback (PRIMARY = shared boot
        // selector; FALLBACK = NV `active_bank`), then target its sibling. The
        // selector mirrors NV, so this picks the same target as the NV-only
        // fallback path did.
        let active = self
            .selector
            .as_ref()
            .and_then(|s| {
                s.read()
                    .expect("selector poisoned")
                    .active_bank(self.bank_set)
            })
            .unwrap_or_else(|| self.fallback_target_active());
        active.other()
    }

    fn prepare_target(&self, bank: Bank) -> Result<(), BankError> {
        // Wipe + space-reclaim the target dir. Seeding from the active bank
        // happens at `seal` time (after the engine has streamed its payloads),
        // mirroring the old `prepare_target_bank_dir` → stream → seed → sign
        // order — seeding here, before any payload arrives, would copy the
        // active files only to have the stream overwrite them.
        self.prepare_target_bank_dir(bank)
    }

    fn open_payload_writer(
        &self,
        bank: Bank,
        name: &str,
    ) -> Result<Box<dyn std::io::Write + Send>, BankError> {
        let bank_dir = self
            .target_bank_dir(bank)
            .ok_or_else(|| BankError::Failed("no images_dir configured".into()))?;
        std::fs::create_dir_all(&bank_dir)?;
        let path = bank_dir.join(name);
        let file = std::fs::File::create(&path)?;
        // 4 MiB buffer (vs the 8 KiB default): the OTA pipeline writes the
        // decompressed bank in 64 KiB chunks, and after the decrypt+decompress
        // speedups the eMMC write became the #1 upload stage (~80 MB/s). Larger,
        // fewer write() syscalls give the device better sequential-write
        // throughput. Flushed by the pipeline before the sink is dropped.
        const WRITE_BUF: usize = 4 * 1024 * 1024;
        Ok(Box::new(BufWriter::with_capacity(WRITE_BUF, file)))
    }

    fn seal(&self, bank: Bank, identity: FirmwareIdentity, gen: u64) -> Result<(), BankError> {
        // Seed unstreamed files from the active bank so the signature below
        // covers a complete bank, not a partial one. No-op for full updates /
        // single-bank / factory. This is the seed step that used to sit right
        // before `ivd_sign_staged_bank` at every engine call site.
        self.seed_target_from_active(bank)?;

        // (1) Test-mode / legitimate no-op skips first — independent of HSM
        //     state (mirrors `ivd_sign_staged_bank`).
        let Some(bank_dir) = self.target_bank_dir(bank) else {
            tracing::debug!("ivd sign: no images_dir; skipping (in-memory test mode)");
            return Ok(());
        };
        if !bank_dir.exists() {
            tracing::debug!(
                bank_dir = %bank_dir.display(),
                "ivd sign: bank dir absent; skipping (pre-streaming path)",
            );
            return Ok(());
        }
        if bank_dir_is_payload_empty(&bank_dir) {
            tracing::debug!(
                bank_dir = %bank_dir.display(),
                "ivd sign: bank dir has no payload files; skipping (HSM bank / out-of-band attestation)",
            );
            return Ok(());
        }

        let bank_id = format!("{}/{}", &self.dir_name, bank_dir_name(bank));

        // (2) Real bank with real payloads → HSM attachment required.
        let hsm_arc = self.hsm.as_ref().ok_or_else(|| {
            BankError::Failed(format!(
                "ivd sign {bank_id}: no HSM provider attached — wiring bug"
            ))
        })?;
        let hsm = hsm_arc
            .lock()
            .map_err(|_| BankError::Failed("ivd sign: hsm mutex poisoned".into()))?;

        // (3) Pre-provisioning exception: HSM reachable but no `ivd-signing`
        //     key yet → skip with a warning (bank intentionally un-sealed).
        match hsm.is_provisioned() {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(
                    bank_id = %bank_id,
                    "ivd sign: HSM not yet provisioned — skipping (bank is not boot-eligible until re-flashed post-provision)",
                );
                return Ok(());
            }
            Err(e) => {
                return Err(BankError::Failed(format!(
                    "ivd sign {bank_id}: hsm provisioning probe failed: {e}"
                )));
            }
        }

        let identity = firmware_to_ivd_identity(&identity);

        // Walk the bank dir + hash every file. The streamed-files fast path
        // (skip the re-hash using the digests the OTA pipeline already
        // computed) re-wires through the `open_payload_writer` seam once the
        // generic engine owns streaming; for now the dir walk produces an
        // identical signed manifest.
        // Sign over the crypto handle (`HsmCryptoProvider`); the `hsm` guard
        // above stays the provisioning authority (the `is_provisioned()` gate).
        // The crypto handle is the only signing path now — `None` while the HSM
        // is provisioned is a wiring bug, surfaced as a clear error.
        let crypto = self.hsm_crypto.as_ref().ok_or_else(|| {
            BankError::Failed(format!(
                "ivd sign {bank_id}: no HSM crypto handle attached — IVD signing needs an HsmCryptoProvider (wiring bug)"
            ))
        })?;
        hsm::ivd::sign_bank_crypto(crypto.as_ref(), &bank_dir, gen, identity)
            .map_err(|e| BankError::Failed(format!("ivd sign {bank_id}: {e}")))?;
        tracing::info!(
            bank_id = %bank_id,
            bank_dir = %bank_dir.display(),
            gen,
            "ivd sign OK",
        );
        Ok(())
    }

    fn read_installed(&self, bank: Bank) -> Result<InstalledFirmware, BankError> {
        let bank_dir = self.target_bank_dir(bank).ok_or(BankError::NotInstalled)?;

        // Report-only read: decode + return the on-disk signed manifest
        // WITHOUT an HSM signature check. We report what the bank is
        // supposed to have installed; the served object carries the raw
        // bytes + signature so the client verifies independently. The real
        // gate (install/boot/launch) stays in `verify_bank`. This path
        // deliberately never touches the HSM, so a diagnostic read keeps
        // working even when the live HSM verify is unavailable (e.g. the
        // IVD public key changed after a guest re-enroll) — the manifest
        // bytes on disk are still intact.
        match hsm::ivd::read_manifest_unverified(&bank_dir) {
            Ok(vm) => {
                let m = &vm.manifest;
                let files = m
                    .files
                    .iter()
                    .map(|f| {
                        let mut sha = [0u8; 32];
                        let n = f.sha256.len().min(32);
                        sha[..n].copy_from_slice(&f.sha256[..n]);
                        InstalledFile {
                            name: f.relative_path.clone(),
                            sha256: sha,
                        }
                    })
                    .collect();
                Ok(InstalledFirmware {
                    bank,
                    gen: m.gen,
                    files,
                    identity: ivd_identity_to_firmware(&m.identity),
                    signature: Some(vm.signature.clone()),
                    raw: Some(vm.manifest_bytes.clone()),
                })
            }
            // Manifest / signature file absent → never flashed (or unsigned).
            Err(hsm::ivd::IvdError::Io(e, _)) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(BankError::NotInstalled)
            }
            // Any other failure (corrupt/undecodable CBOR, unsupported
            // version, non-NotFound I/O) — there is no `SignatureInvalid`
            // outcome on the report-only path.
            Err(e) => Err(BankError::Failed(format!("read_installed: {e}"))),
        }
    }

    fn verify_payload(
        &self,
        bank: Bank,
        name: &str,
        expected_sha256: &[u8; 32],
    ) -> Result<(), BankError> {
        let bank_dir = self
            .target_bank_dir(bank)
            .ok_or_else(|| BankError::Failed("no images_dir configured".into()))?;
        let path = bank_dir.join(name);
        // Stream the hash in 64 KiB chunks — NEVER `std::fs::read` the whole
        // image into a Vec. A rootfs is hundreds of MB; the one-shot read
        // pre-sizes a contiguous Vec to the file length and OOMs a
        // memory-pressured CVC (`verify_payload read …: out of memory`), which
        // then surfaces as a bank/verify failure. `hash_reader` is O(64 KiB)
        // resident — same idiom as the upload pipeline's `process_plain`.
        let file = std::fs::File::open(&path).map_err(|e| {
            BankError::Failed(format!("verify_payload read {}: {e}", path.display()))
        })?;
        let (_len, recomputed) = crate::streaming::hash_reader(std::io::BufReader::new(file))
            .map_err(|e| {
                BankError::Failed(format!("verify_payload read {}: {e}", path.display()))
            })?;
        if &recomputed == expected_sha256 {
            Ok(())
        } else {
            Err(BankError::Unverifiable(format!(
                "{name}: inner sha256 mismatch on disk — recomputed {} vs captured {}",
                hex::encode(recomputed),
                hex::encode(expected_sha256)
            )))
        }
    }

    fn activate(&self, bank: Bank) -> Result<ResetKind, BankError> {
        // Run the activator (IFS write, partition swap, RT launcher …) FIRST so
        // a failure short-circuits with `?` BEFORE the selector below is sealed:
        // the engine can then roll NV back without the boot selector pointing at
        // a half-activated bank.
        //
        // For VMs (`bank_activator == None`) the block is skipped — VMs have no
        // activator; their qvm/process cycle is the activation. This matches the
        // finalize block that is skipped when no activator is configured.
        if let (Some(activator), Some(images_dir)) =
            (self.bank_activator.as_ref(), self.images_dir.as_ref())
        {
            let bank_dir = images_dir.join(&self.dir_name).join(bank_dir_name(bank));
            activator
                .activate(&bank_dir)
                .map_err(|e| BankError::Failed(format!("bank activation failed: {e}")))?;
        }
        // Record the activation in the boot selector (the boot authority): stage
        // + seal so the selector's PRIMARY now reflects the just-activated bank.
        // VMs (no activator) skip the block above but still record the new bank
        // here — the selector tracks the activation regardless of how it
        // physically happened.
        //
        // TODO(campaign): the selector's seal/commit/rollback are GLOBAL (whole
        // blob); correct only while <=1 component is mid-trial (the
        // per-component flash-guard + one-OTA-at-a-time make that the norm —
        // non-trial components have PRIMARY==SECONDARY so the global op no-ops
        // them). A future campaign coordinator handles concurrent trials.
        if let Some(sel) = &self.selector {
            let mut g = sel.write().expect("selector poisoned");
            g.stage(self.bank_set, bank);
            g.seal();
        }
        Ok(self.reset_kind())
    }

    fn commit(&self) -> Result<(), BankError> {
        let mut nv = self
            .nv
            .lock()
            .map_err(|_| BankError::Failed("nv lock poisoned".into()))?;
        match ota::commit(&mut nv, self.bank_set) {
            Ok(()) => {}
            // CRL / idempotent commit — already committed is fine.
            Err(ota::OtaError::AlreadyCommitted) => {}
            Err(e) => return Err(BankError::Failed(e.to_string())),
        }
        // Dual-write: promote the selector's PRIMARY to SECONDARY (rollback
        // floor) — see the GLOBAL-op caveat on `activate`.
        if let Some(sel) = &self.selector {
            sel.write().expect("selector poisoned").commit();
        }
        Ok(())
    }

    fn rollback(&self) -> Result<(), BankError> {
        {
            let mut nv = self
                .nv
                .lock()
                .map_err(|_| BankError::Failed("nv lock poisoned".into()))?;
            ota::rollback(&mut nv, self.bank_set)
                .map(|_| ())
                .map_err(|e| BankError::Failed(e.to_string()))?;
        }
        // Dual-write: roll the selector's PRIMARY back to the committed floor
        // (SECONDARY) — see the GLOBAL-op caveat on `activate`.
        if let Some(sel) = &self.selector {
            sel.write().expect("selector poisoned").rollback();
        }
        Ok(())
    }

    fn reset_kind(&self) -> ResetKind {
        self.bank_activator
            .as_ref()
            .map(|a| a.reset_kind())
            .unwrap_or(ResetKind::Local)
    }
}

/// On-disk dir name for a bank (`bank_a` / `bank_b`).
pub fn bank_dir_name(bank: Bank) -> &'static str {
    match bank {
        Bank::A => "bank_a",
        Bank::B => "bank_b",
    }
}

/// `true` if `bank_dir` has no files that IVD signing would attest to. Skips
/// IVD's own outputs (manifest + signature) so a re-sign doesn't trip on a
/// previous run's artefacts.
fn bank_dir_is_payload_empty(bank_dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(bank_dir) else {
        return true;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if name == hsm::ivd::IVD_MANIFEST_FILE || name == hsm::ivd::IVD_SIGNATURE_FILE {
            continue;
        }
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use machine_mgr::system_bank_state::{
        InMemorySelectorStore, SharedSystemBankState, SystemBankManager, TestSigner,
    };
    use nv_store::block::MemBlockDevice;
    use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
    use nv_store::types::NvBootState;
    use std::sync::RwLock;

    /// NV with `active_bank` set to `active` for `set`, so the
    /// `running_bank`/symlink fallback resolves to a known bank distinct from
    /// the selector's choice.
    fn nv_with_active(set: BankSet, active: Bank) -> Arc<Mutex<NvStore<MemBlockDevice>>> {
        let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
        let mut nv = NvStore::new(dev);
        let mut state = NvBootState::default();
        state.banks[set.as_index()].active_bank = active;
        nv.write_boot_state(&mut state).unwrap();
        Arc::new(Mutex::new(nv))
    }

    /// A shared boot selector seeded so `set` boots from `bank` (PRIMARY).
    fn selector_with(set: BankSet, bank: Bank) -> SharedSystemBankState {
        let mgr =
            SystemBankManager::load(Box::new(InMemorySelectorStore::new()), Box::new(TestSigner));
        let shared: SharedSystemBankState = Arc::new(RwLock::new(mgr));
        {
            let mut g = shared.write().unwrap();
            g.stage(set, bank);
            assert!(g.seal());
            assert_eq!(g.active_bank(set), Some(bank));
        }
        shared
    }

    fn provider(
        nv: Arc<Mutex<NvStore<MemBlockDevice>>>,
        set: BankSet,
        selector: Option<SharedSystemBankState>,
    ) -> IvdBankProvider<MemBlockDevice> {
        IvdBankProvider::new(nv, set, false, None, "vm1".into(), None, None, selector)
    }

    #[test]
    fn injected_selector_is_primary_source_for_active_and_target() {
        let set = BankSet::Vm1;
        // NV/fallback says A; the injected selector says B — the selector wins.
        let nv = nv_with_active(set, Bank::A);
        let selector = selector_with(set, Bank::B);
        let p = provider(nv, set, Some(selector));

        assert_eq!(
            p.active_bank(),
            Bank::B,
            "selector (B) is primary, not NV (A)"
        );
        assert_eq!(
            p.target_bank(),
            Bank::A,
            "target is the sibling of the selector's active bank"
        );
    }

    #[test]
    fn no_selector_falls_back_to_running_bank() {
        let set = BankSet::Vm1;
        // No selector injected → active_bank reads the NV-seeded running_bank.
        let nv = nv_with_active(set, Bank::B);
        let p = provider(nv, set, None);

        assert_eq!(
            p.active_bank(),
            Bank::B,
            "fallback: running_bank seeded from NV active_bank (B)"
        );
        assert_eq!(p.target_bank(), Bank::A, "fallback target is the sibling");
    }

    #[test]
    fn selector_without_entry_for_set_falls_back_to_nv() {
        // Selector populated for a DIFFERENT set leaves this set unselected →
        // active_bank falls through to the NV/running_bank fallback.
        let set = BankSet::Vm1;
        let nv = nv_with_active(set, Bank::B);
        let selector = selector_with(BankSet::Vm2, Bank::A);
        let p = provider(nv, set, Some(selector));

        assert_eq!(
            p.active_bank(),
            Bank::B,
            "no selection for Vm1 → NV fallback (B)"
        );
    }

    #[test]
    fn activate_writes_selector_primary() {
        // The OTA write path: a provider holding the shared selector (VM shape
        // — no activator/images_dir, so `activate` only does the selector
        // dual-write) must move the selector's PRIMARY to the activated bank.
        let set = BankSet::Vm1;
        // Selector + NV both start at A; activate(B) must flip PRIMARY to B.
        let nv = nv_with_active(set, Bank::A);
        let selector = selector_with(set, Bank::A);
        // Keep a write-handle clone so we can read PRIMARY back after activate.
        let p = provider(nv, set, Some(Arc::clone(&selector)));
        assert_eq!(
            selector.read().unwrap().active_bank(set),
            Some(Bank::A),
            "precondition: selector PRIMARY is A"
        );

        p.activate(Bank::B).expect("activate B");

        assert_eq!(
            selector.read().unwrap().active_bank(set),
            Some(Bank::B),
            "activate(B) wrote the selector PRIMARY to B (OTA dual-write)"
        );
        // And the provider now reads B as active through the same selector.
        assert_eq!(p.active_bank(), Bank::B);
    }

    // ---------------------------------------------------------------------
    // read_installed is REPORT-ONLY: decode the on-disk signed manifest with
    // no HSM verify. It must report even when the signature would not verify,
    // and never call into the HSM.
    // ---------------------------------------------------------------------

    /// Provision a `SimHsm`, sign `gen` into `bank_dir`, and return the HSM +
    /// keystore path (to clean up). Mirrors hsm's own `provisioned_sim`.
    fn sign_bank_dir(name: &str, bank_dir: &Path, gen: u64) -> (hsm_sim_backend::SimHsm, PathBuf) {
        use hsm::payload::*;
        let keystore = std::env::temp_dir().join(format!("component-mgr-readinstalled-ks-{name}"));
        let _ = std::fs::remove_dir_all(&keystore);
        std::fs::create_dir_all(&keystore).unwrap();

        let hsm = hsm_sim_backend::SimHsm::new(keystore.clone());
        let ks = HsmKeystore {
            schema_version: SCHEMA_VERSION,
            security_version: 1,
            identities: vec![],
            slots: vec![KeySlot {
                key_id: hsm::ivd::IVD_KEY_ID.to_string(),
                key_kind: KEY_TYPE_EC_P256,
                anchor_public_key: None,
                allowed_guests: None,
                allowed_ops: Some(vec![OP_SIGN, OP_VERIFY, OP_GET_PUBKEY]),
            }],
            certificates: Vec::new(),
            trust_anchors: Vec::new(),
        };
        hsm.write_keystore(&ks).unwrap();
        std::fs::write(keystore.join("provision_state"), b"1\n").unwrap();

        std::fs::create_dir_all(bank_dir).unwrap();
        std::fs::write(bank_dir.join("kernel"), b"kernel bytes").unwrap();
        // Non-empty identity so the manifest's final CBOR byte is string
        // content — flipping it in the tamper test keeps the CBOR decodable.
        let identity = hsm::ivd::IvdIdentity {
            version: "1.2.0".into(),
            ecu_sw_number: "VM1-SW-001".into(),
            tester_serial: "SOVD-OTA".into(),
            ..Default::default()
        };
        hsm::ivd::sign_bank_crypto(&hsm, bank_dir, gen, identity).unwrap();
        (hsm, keystore)
    }

    /// An `images_dir`-backed provider with NO HSM wired — proves the
    /// report-only read needs none.
    fn disk_provider_no_hsm(images_dir: PathBuf) -> IvdBankProvider<MemBlockDevice> {
        let nv = nv_with_active(BankSet::Vm1, Bank::A);
        IvdBankProvider::new(
            nv,
            BankSet::Vm1,
            false,
            Some(images_dir),
            "vm1".into(),
            None, // <- no HSM
            None,
            None,
        )
    }

    #[test]
    fn read_installed_reports_even_when_signature_would_not_verify_and_without_hsm() {
        let images_dir = std::env::temp_dir().join("component-mgr-readinstalled-tamper");
        let _ = std::fs::remove_dir_all(&images_dir);
        let bank_dir = images_dir.join("vm1").join("bank_b");
        let (_hsm, keystore) = sign_bank_dir("tamper", &bank_dir, 7);

        // Tamper a byte: still decodable, but the signature no longer matches.
        let mpath = bank_dir.join(hsm::ivd::IVD_MANIFEST_FILE);
        let mut bytes = std::fs::read(&mpath).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&mpath, &bytes).unwrap();

        // Provider has NO HSM — read_installed still reports the bank.
        let p = disk_provider_no_hsm(images_dir.clone());
        let fw = p
            .read_installed(Bank::B)
            .expect("report-only read_installed must succeed with a bad signature and no HSM");
        assert_eq!(fw.bank, Bank::B);
        assert_eq!(fw.gen, 7);
        // The raw artefacts are handed up for the client to verify itself, and
        // they are the exact tampered on-disk bytes.
        assert_eq!(fw.raw.as_deref(), Some(bytes.as_slice()));
        assert!(fw.signature.is_some());

        let _ = std::fs::remove_dir_all(&images_dir);
        let _ = std::fs::remove_dir_all(&keystore);
    }

    #[test]
    fn read_installed_not_installed_when_manifest_absent() {
        let images_dir = std::env::temp_dir().join("component-mgr-readinstalled-absent");
        let _ = std::fs::remove_dir_all(&images_dir);
        // Create the bank dir + a payload file but NO signed manifest.
        let bank_dir = images_dir.join("vm1").join("bank_b");
        std::fs::create_dir_all(&bank_dir).unwrap();
        std::fs::write(bank_dir.join("kernel"), b"kernel bytes").unwrap();

        let p = disk_provider_no_hsm(images_dir.clone());
        match p.read_installed(Bank::B) {
            Err(BankError::NotInstalled) => {}
            other => panic!("expected NotInstalled, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&images_dir);
    }

    /// verify_payload streams the hash (no whole-file read) and passes when the
    /// on-disk bytes match the captured digest. Uses a payload comfortably
    /// larger than the 64 KiB chunk so the multi-iteration loop is exercised.
    #[test]
    fn verify_payload_matches_streamed_hash() {
        use sha2::{Digest, Sha256};
        let images_dir = std::env::temp_dir().join("component-mgr-verify-match");
        let _ = std::fs::remove_dir_all(&images_dir);
        let bank_dir = images_dir.join("vm1").join("bank_b");
        std::fs::create_dir_all(&bank_dir).unwrap();
        // 200 KiB: > 3 chunks, proves the loop (not a single read) is correct.
        let payload = vec![0xABu8; 200 * 1024];
        std::fs::write(bank_dir.join("rootfs.img"), &payload).unwrap();
        let expected: [u8; 32] = Sha256::digest(&payload).into();

        let p = disk_provider_no_hsm(images_dir.clone());
        p.verify_payload(Bank::B, "rootfs.img", &expected)
            .expect("streamed hash of matching bytes must verify");

        let _ = std::fs::remove_dir_all(&images_dir);
    }

    /// A one-byte mismatch → Unverifiable (a clean digest failure), not Failed.
    #[test]
    fn verify_payload_mismatch_is_unverifiable() {
        use sha2::{Digest, Sha256};
        let images_dir = std::env::temp_dir().join("component-mgr-verify-mismatch");
        let _ = std::fs::remove_dir_all(&images_dir);
        let bank_dir = images_dir.join("vm1").join("bank_b");
        std::fs::create_dir_all(&bank_dir).unwrap();
        let payload = vec![0x11u8; 100 * 1024];
        std::fs::write(bank_dir.join("rootfs.img"), &payload).unwrap();
        // Digest of DIFFERENT bytes → mismatch on disk.
        let wrong: [u8; 32] = Sha256::digest(b"not the payload").into();

        let p = disk_provider_no_hsm(images_dir.clone());
        match p.verify_payload(Bank::B, "rootfs.img", &wrong) {
            Err(BankError::Unverifiable(_)) => {}
            other => panic!("expected Unverifiable on digest mismatch, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&images_dir);
    }

    /// A missing payload file → Failed with the `verify_payload read …` prefix
    /// (the same error shape the OOM used to take — now only real I/O errors,
    /// never allocation failure, land here).
    #[test]
    fn verify_payload_missing_file_is_failed() {
        let images_dir = std::env::temp_dir().join("component-mgr-verify-missing");
        let _ = std::fs::remove_dir_all(&images_dir);
        std::fs::create_dir_all(images_dir.join("vm1").join("bank_b")).unwrap();

        let p = disk_provider_no_hsm(images_dir.clone());
        match p.verify_payload(Bank::B, "absent.img", &[0u8; 32]) {
            Err(BankError::Failed(msg)) => {
                assert!(msg.contains("verify_payload read"), "got: {msg}");
            }
            other => panic!("expected Failed on missing file, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&images_dir);
    }
}
