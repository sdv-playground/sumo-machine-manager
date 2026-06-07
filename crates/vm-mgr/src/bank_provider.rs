//! `IvdBankProvider` — the IVD/A-B implementation of
//! [`machine_mgr::BankProvider`] for vm-mgr bank sets.
//!
//! This is the default `BankProvider`: a signed CBOR IVD manifest living in
//! a bank dir, a `current` symlink flip for activation, and NV boot-state for
//! the A/B + trial + commit/rollback lifecycle. It owns every *bank touch*
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

/// The IVD/A-B [`BankProvider`]: signed CBOR manifest in a bank dir, `current`
/// symlink flip, NV boot-state. Backs VMs, host-os and hsm bank sets.
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
    /// HSM provider used to sign / signature-verify the IVD manifest.
    hsm: Option<Arc<Mutex<dyn hsm::HsmProvider>>>,
    /// Activator invoked by `activate()` BEFORE the symlink flip (RT launcher,
    /// IFS write, ...) — on failure the flip is skipped so the engine can roll
    /// NV back without a stale `current` pointer. `None` for VMs whose
    /// qvm/process cycle is the activation (they never flip here).
    bank_activator: Option<Arc<dyn machine_mgr::BankActivator>>,
    /// The bank the ECU is actually running on. Seeded from NV at construction
    /// (NV `active_bank` may differ after install — that's the *next-boot*
    /// bank). The engine keeps its own running-bank for its read paths; this
    /// copy backs only `active_bank()` / `target_bank()` as the **fallback**
    /// when no shared boot selector is injected.
    running_bank: Mutex<Bank>,
    /// The node's shared, signed boot selector — the **write** handle
    /// (`Arc<RwLock<SystemBankManager>>`). When present it is the **PRIMARY**
    /// source for `active_bank()` / `target_bank()` (`running_bank` / the
    /// `current` symlink are the fallback) AND the OTA write path stages /
    /// seals / commits / rolls it back so it tracks the real bank. `None` for
    /// tests and the inline construction in `backend.rs` (no selector wired),
    /// which preserves the prior NV/symlink-only behaviour.
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
            bank_activator,
            running_bank: Mutex::new(running_bank),
            selector,
        }
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

    /// Read the `current` symlink under `images_dir/<dir_name>/` and return
    /// the bank it points to, or `None` if missing / unreadable.
    fn read_current_symlink(&self) -> Option<Bank> {
        let images_dir = self.images_dir.as_ref()?;
        let symlink_path = images_dir.join(&self.dir_name).join("current");
        let target = std::fs::read_link(&symlink_path).ok()?;
        let name = target.file_name()?.to_str()?;
        match name {
            "bank_a" => Some(Bank::A),
            "bank_b" => Some(Bank::B),
            _ => None,
        }
    }

    /// The booted bank from the **fallback** source used by `active_bank()`
    /// when no boot selector is injected: the `running_bank` copy seeded from
    /// NV at construction (only changes on `ecu_reset`). Unchanged from the
    /// pre-selector behaviour.
    fn fallback_active_bank(&self) -> Bank {
        *self.running_bank.lock().expect("running_bank poisoned")
    }

    /// The booted bank from the **fallback** source used by `target_bank()`
    /// when no boot selector is injected: the `current` symlink (source of
    /// truth for activator-backed components — it survives factory resets),
    /// falling back to NV `active_bank` when no symlink exists (first-ever
    /// flash). Unchanged from the pre-selector behaviour. Single-bank is
    /// handled by the caller (always targets `Bank::A`).
    fn fallback_target_active(&self) -> Bank {
        if self.bank_activator.is_some() {
            if let Some(active) = self.read_current_symlink() {
                return active;
            }
        }
        let nv = match self.nv.lock() {
            Ok(nv) => nv,
            Err(_) => return Bank::A,
        };
        nv.read_boot_state()
            .map(|s| s.banks[self.bank_set.as_index()].active_bank)
            .unwrap_or(Bank::A)
    }

    /// Atomically flip the `current` symlink to point at `bank`. Internal to
    /// the provider: `activate` calls it AFTER the activator succeeds (the
    /// activator-then-flip order). The engine no longer flips directly — its
    /// install/finalize path routes entirely through `activate`, and
    /// `ecu_reset` does its own running-bank flip.
    fn flip_current_symlink(&self, bank: Bank) {
        let Some(images_dir) = self.images_dir.as_ref() else {
            return;
        };
        let dir = images_dir.join(&self.dir_name);
        let symlink_path = dir.join("current");
        let target = Path::new(bank_dir_name(bank));
        let tmp_link = symlink_path.with_extension("tmp");
        let _ = std::fs::remove_file(&tmp_link);
        if let Err(e) = std::os::unix::fs::symlink(target, &tmp_link)
            .and_then(|()| std::fs::rename(&tmp_link, &symlink_path))
        {
            tracing::warn!(
                bank_set = ?self.bank_set,
                "failed to flip current symlink: {e}"
            );
        } else {
            tracing::info!(
                bank_set = ?self.bank_set,
                bank = ?bank,
                "flipped current -> {}",
                bank_dir_name(bank),
            );
        }
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
fn firmware_to_ivd_identity(id: &FirmwareIdentity) -> hsm::ivd::IvdIdentity {
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
        // selector; FALLBACK = `current` symlink, then NV `active_bank`), then
        // target its sibling. The selector mirrors NV, so this picks the same
        // target as the symlink/NV-only path did.
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
        Ok(Box::new(BufWriter::new(file)))
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
        hsm::ivd::sign_bank(&*hsm, &bank_dir, gen, identity)
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
        let hsm_arc = self.hsm.as_ref().ok_or(BankError::NotInstalled)?;
        let hsm = hsm_arc
            .lock()
            .map_err(|_| BankError::Failed("read_installed: hsm mutex poisoned".into()))?;

        match hsm::ivd::read_manifest(&*hsm, &bank_dir) {
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
            Err(hsm::ivd::IvdError::SignatureInvalid) => {
                Err(BankError::Unverifiable("ivd signature invalid".into()))
            }
            Err(e) => Err(BankError::Failed(format!("read_installed: {e}"))),
        }
    }

    fn verify_payload(
        &self,
        bank: Bank,
        name: &str,
        expected_sha256: &[u8; 32],
    ) -> Result<(), BankError> {
        use sha2::{Digest, Sha256};
        let bank_dir = self
            .target_bank_dir(bank)
            .ok_or_else(|| BankError::Failed("no images_dir configured".into()))?;
        let path = bank_dir.join(name);
        let bytes = std::fs::read(&path).map_err(|e| {
            BankError::Failed(format!("verify_payload read {}: {e}", path.display()))
        })?;
        let recomputed: [u8; 32] = Sha256::digest(&bytes).into();
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
        // Activator-then-flip (the live finalize order, NOT the old dead-code
        // flip-then-activator): run the activator FIRST so a failure leaves the
        // `current` symlink pointing at the previously-active bank, and the
        // engine can roll NV back without a stale pointer to the half-activated
        // bank. Only flip once the activator has succeeded.
        //
        // For VMs (`bank_activator == None`) the whole block is skipped — VMs
        // never flip here; their qvm/process cycle is the activation, and
        // `ecu_reset` flips the `current` symlink at reset time. This matches
        // the finalize block that is skipped when no activator is configured.
        if let (Some(activator), Some(images_dir)) =
            (self.bank_activator.as_ref(), self.images_dir.as_ref())
        {
            let bank_dir = images_dir.join(&self.dir_name).join(bank_dir_name(bank));
            activator
                .activate(&bank_dir)
                .map_err(|e| BankError::Failed(format!("bank activation failed: {e}")))?;
            self.flip_current_symlink(bank);
        }
        // Dual-write the boot selector alongside the NV/symlink state: stage +
        // seal so the selector's PRIMARY now reflects the just-activated bank.
        // VMs (no activator) skip the block above but still record the new bank
        // here — the selector must track the activation regardless of how it
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
}
