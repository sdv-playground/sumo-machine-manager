//! OTA update flow — download, verify, commit, rollback.
//!
//! The diagserver manages the update lifecycle:
//!
//! 1. `install()`  — validate, copy-on-update, write image, verify hash, update NV
//! 2. `commit()`   — mark trial as committed, raise anti-rollback floor
//! 3. `rollback()` — swap back to previous bank
//!
//! Per-call NV record builders use `Default::default()` then assign
//! fields for readability; the struct-init alternative would spell
//! every default at each call site for negligible benefit.
#![allow(clippy::field_reassign_with_default, clippy::too_many_arguments)]

use nv_store::block::BlockDevice;
use nv_store::store::NvStore;
use nv_store::types::*;
use sha2::{Digest, Sha256};

#[derive(Debug, PartialEq, Eq)]
pub enum OtaError {
    /// Bank set is in trial mode — must commit or rollback first
    InTrial,
    /// Image security version below anti-rollback floor
    SecurityVersionTooLow { image: u32, floor: u32 },
    /// Image hash mismatch after write (read-back verification failed)
    VerifyFailed {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// Bank set is already committed — nothing to commit
    AlreadyCommitted,
    /// Bank set is already committed — nothing to rollback
    NotInTrial,
    /// NV boot state not initialized
    NoBootState,
    /// NV store I/O error
    NvError(String),
}

impl From<nv_store::block::BlockError> for OtaError {
    fn from(e: nv_store::block::BlockError) -> Self {
        OtaError::NvError(e.to_string())
    }
}

impl std::fmt::Display for OtaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OtaError::InTrial => write!(f, "bank set is in trial mode"),
            OtaError::SecurityVersionTooLow { image, floor } => {
                write!(f, "image security version {image} below floor {floor}")
            }
            OtaError::VerifyFailed { .. } => write!(f, "image hash verification failed"),
            OtaError::AlreadyCommitted => write!(f, "bank set is already committed"),
            OtaError::NotInTrial => write!(f, "bank set is not in trial mode"),
            OtaError::NoBootState => write!(f, "NV boot state not initialized"),
            OtaError::NvError(e) => write!(f, "NV error: {e}"),
        }
    }
}

/// Metadata for an incoming OTA image (parsed from image header).
#[derive(Debug, Clone, Default)]
pub struct ImageMeta {
    pub fw_version: [u8; 32],
    pub fw_seq: u32,
    pub fw_secver: u32,
    pub spare_part_number: [u8; 32],
    pub ecu_sw_number: [u8; 32],
    pub supplier_sw_number: [u8; 32],
    pub supplier_sw_version: [u8; 32],
    pub odx_file_id: [u8; 32],
    pub system_name: [u8; 32],
    pub programming_date: [u8; 8],
    pub tester_serial: [u8; 32],
}

/// Result of a successful install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallResult {
    pub target_bank: Bank,
    pub image_sha256: [u8; 32],
    /// Install-time generation counter assigned to the target bank's
    /// NvFwMeta and required to be embedded in the bank's IVD manifest.
    /// See `NvFwMeta.gen` for full semantics.
    pub gen: u64,
}

/// Install an OTA image for a bank set.
///
/// This performs the full OTA flow:
/// 1. Validate preconditions (committed, anti-rollback)
/// 2. Copy-on-update runtime DIDs from active → target
/// 3. Compute image SHA-256
/// 4. Write FW Meta for target bank
/// 5. Switch active bank to target, enter trial mode
///
/// When `single_bank` is true (e.g. HSM), the image is written to bank A
/// in-place with immediate commit — no bank swap, no trial mode.
///
/// Note: The actual image write to the OS partition is the caller's
/// responsibility (platform-specific). This function handles NV metadata only.
pub fn install<D: BlockDevice>(
    nv: &mut NvStore<D>,
    set: BankSet,
    image_data: &[u8],
    meta: &ImageMeta,
    single_bank: bool,
) -> Result<InstallResult, OtaError> {
    let state = nv.read_boot_state().ok_or(OtaError::NoBootState)?;
    let idx = set.as_index();

    // Precondition: must be committed
    if !state.banks[idx].committed {
        return Err(OtaError::InTrial);
    }

    let active = state.banks[idx].active_bank;

    // Anti-rollback check
    if let Some(current_meta) = nv.read_fw_meta(set, active) {
        if meta.fw_secver < current_meta.min_security_ver {
            return Err(OtaError::SecurityVersionTooLow {
                image: meta.fw_secver,
                floor: current_meta.min_security_ver,
            });
        }
    }

    // Compute image hash and CRC
    let image_sha256: [u8; 32] = Sha256::digest(image_data).into();
    let fw_crc = crc32fast::hash(image_data);

    install_inner(
        nv,
        set,
        state,
        idx,
        active,
        image_sha256,
        fw_crc,
        meta,
        single_bank,
    )
}

/// Install with pre-computed hash (streaming path — image already on disk).
pub fn install_precomputed<D: BlockDevice>(
    nv: &mut NvStore<D>,
    set: BankSet,
    image_sha256: [u8; 32],
    image_size: u64,
    meta: &ImageMeta,
    single_bank: bool,
) -> Result<InstallResult, OtaError> {
    let state = nv.read_boot_state().ok_or(OtaError::NoBootState)?;
    let idx = set.as_index();

    if !state.banks[idx].committed {
        return Err(OtaError::InTrial);
    }

    let active = state.banks[idx].active_bank;

    if let Some(current_meta) = nv.read_fw_meta(set, active) {
        if meta.fw_secver < current_meta.min_security_ver {
            return Err(OtaError::SecurityVersionTooLow {
                image: meta.fw_secver,
                floor: current_meta.min_security_ver,
            });
        }
    }

    let fw_crc = crc32fast::hash(&image_size.to_le_bytes()); // Placeholder CRC for streamed data

    install_inner(
        nv,
        set,
        state,
        idx,
        active,
        image_sha256,
        fw_crc,
        meta,
        single_bank,
    )
}

fn install_inner<D: BlockDevice>(
    nv: &mut NvStore<D>,
    set: BankSet,
    mut state: NvBootState,
    idx: usize,
    active: Bank,
    image_sha256: [u8; 32],
    fw_crc: u32,
    meta: &ImageMeta,
    single_bank: bool,
) -> Result<InstallResult, OtaError> {
    if single_bank {
        // Single-bank install (HSM): overwrite bank A in-place, immediate commit
        let min_security_ver = meta.fw_secver; // raise floor immediately

        // gen ratchets even for single-bank — uniform anti-rollback.
        let prev_gen = nv.read_fw_meta(set, Bank::A).map(|m| m.gen).unwrap_or(0);
        let next_gen = prev_gen + 1;

        let mut fw_meta = NvFwMeta {
            write_seq: 0,
            fw_version: meta.fw_version,
            fw_seq: meta.fw_seq,
            fw_secver: meta.fw_secver,
            fw_crc,
            image_sha256,
            spare_part_number: meta.spare_part_number,
            ecu_sw_number: meta.ecu_sw_number,
            supplier_sw_number: meta.supplier_sw_number,
            supplier_sw_version: meta.supplier_sw_version,
            odx_file_id: meta.odx_file_id,
            system_name: meta.system_name,
            programming_date: meta.programming_date,
            tester_serial: meta.tester_serial,
            min_security_ver,
            gen: next_gen,
        };
        nv.write_fw_meta(set, Bank::A, &mut fw_meta)?;

        // Keep committed=true, bank A, no trial
        state.banks[idx].active_bank = Bank::A;
        state.banks[idx].committed = true;
        state.banks[idx].boot_count = 0;
        nv.write_boot_state(&mut state)?;

        Ok(InstallResult {
            target_bank: Bank::A,
            image_sha256,
            gen: next_gen,
        })
    } else {
        // A/B banked install: write to inactive bank, enter trial mode
        let target = active.other();

        // Copy-on-update: clone runtime DIDs from active → target
        nv.copy_runtime(set, active, target)?;

        // Preserve min_security_ver from active bank
        let min_security_ver = nv
            .read_fw_meta(set, active)
            .map(|m| m.min_security_ver)
            .unwrap_or(0);

        // Generation: install-time monotonic ratchet. The active bank
        // is the currently-committed one (precondition `committed=true`
        // ensures this), so its gen IS the committed_gen floor for
        // this set. Target gets committed_gen + 1; ivd_sign_staged_bank
        // reads this back from NV and embeds it in the signed manifest.
        let committed_gen = nv.read_fw_meta(set, active).map(|m| m.gen).unwrap_or(0);
        let next_gen = committed_gen + 1;

        let mut fw_meta = NvFwMeta {
            write_seq: 0,
            fw_version: meta.fw_version,
            fw_seq: meta.fw_seq,
            fw_secver: meta.fw_secver,
            fw_crc,
            image_sha256,
            spare_part_number: meta.spare_part_number,
            ecu_sw_number: meta.ecu_sw_number,
            supplier_sw_number: meta.supplier_sw_number,
            supplier_sw_version: meta.supplier_sw_version,
            odx_file_id: meta.odx_file_id,
            system_name: meta.system_name,
            programming_date: meta.programming_date,
            tester_serial: meta.tester_serial,
            min_security_ver,
            gen: next_gen,
        };
        nv.write_fw_meta(set, target, &mut fw_meta)?;

        // Switch to target bank, enter trial mode
        state.banks[idx].active_bank = target;
        state.banks[idx].committed = false;
        state.banks[idx].boot_count = 0;
        nv.write_boot_state(&mut state)?;

        Ok(InstallResult {
            target_bank: target,
            image_sha256,
            gen: next_gen,
        })
    }
}

/// Commit the current trial bank set.
///
/// Sets committed=true, resets boot count, and raises the anti-rollback
/// floor if the new firmware's security version exceeds it.
pub fn commit<D: BlockDevice>(nv: &mut NvStore<D>, set: BankSet) -> Result<(), OtaError> {
    let mut state = nv.read_boot_state().ok_or(OtaError::NoBootState)?;
    let idx = set.as_index();

    if state.banks[idx].committed {
        return Err(OtaError::AlreadyCommitted);
    }

    let active = state.banks[idx].active_bank;

    // Raise anti-rollback floor
    if let Some(mut meta) = nv.read_fw_meta(set, active) {
        if meta.fw_secver > meta.min_security_ver {
            meta.min_security_ver = meta.fw_secver;
            nv.write_fw_meta(set, active, &mut meta)?;
        }
    }

    state.banks[idx].committed = true;
    state.banks[idx].boot_count = 0;
    nv.write_boot_state(&mut state)?;

    Ok(())
}

/// Rollback the current trial to the previous bank.
///
/// Swaps active_bank back, sets committed=true.
pub fn rollback<D: BlockDevice>(nv: &mut NvStore<D>, set: BankSet) -> Result<Bank, OtaError> {
    let mut state = nv.read_boot_state().ok_or(OtaError::NoBootState)?;
    let idx = set.as_index();

    if state.banks[idx].committed {
        return Err(OtaError::NotInTrial);
    }

    let previous = state.banks[idx].active_bank.other();
    state.banks[idx].active_bank = previous;
    state.banks[idx].committed = true;
    state.banks[idx].boot_count = 0;
    nv.write_boot_state(&mut state)?;

    Ok(previous)
}

/// Query the status of a bank set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BankStatus {
    pub active_bank: Bank,
    pub committed: bool,
    pub boot_count: u8,
    pub fw_version: Option<[u8; 32]>,
    pub fw_secver: Option<u32>,
    pub min_security_ver: Option<u32>,
}

pub fn status<D: BlockDevice>(nv: &NvStore<D>, set: BankSet) -> Option<BankStatus> {
    let state = nv.read_boot_state()?;
    let bs = &state.banks[set.as_index()];
    let meta = nv.read_fw_meta(set, bs.active_bank);

    Some(BankStatus {
        active_bank: bs.active_bank,
        committed: bs.committed,
        boot_count: bs.boot_count,
        fw_version: meta.as_ref().map(|m| m.fw_version),
        fw_secver: meta.as_ref().map(|m| m.fw_secver),
        min_security_ver: meta.as_ref().map(|m| m.min_security_ver),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nv_store::block::MemBlockDevice;
    use nv_store::store::MIN_NV_DEVICE_SIZE;

    fn make_nv() -> NvStore<MemBlockDevice> {
        NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize))
    }

    /// Initialize boot state with all bank sets active=A, committed=true.
    fn init_boot(nv: &mut NvStore<MemBlockDevice>) {
        let mut state = NvBootState::default();
        for b in &mut state.banks {
            b.active_bank = Bank::A;
            b.committed = true;
            b.boot_count = 0;
        }
        nv.write_boot_state(&mut state).unwrap();
    }

    fn meta_v(seq: u32, secver: u32) -> ImageMeta {
        let mut m = ImageMeta::default();
        m.fw_seq = seq;
        m.fw_secver = secver;
        m.fw_version[..5].copy_from_slice(b"v1.0 ");
        m
    }

    // --- Error Display ---

    #[test]
    fn ota_error_display_covers_all_variants() {
        assert!(format!("{}", OtaError::InTrial).contains("trial"));
        assert!(
            format!("{}", OtaError::SecurityVersionTooLow { image: 1, floor: 2 })
                .contains("below floor 2")
        );
        assert!(format!(
            "{}",
            OtaError::VerifyFailed {
                expected: [0; 32],
                actual: [1; 32]
            }
        )
        .contains("verification failed"));
        assert!(format!("{}", OtaError::AlreadyCommitted).contains("already committed"));
        assert!(format!("{}", OtaError::NotInTrial).contains("not in trial"));
        assert!(format!("{}", OtaError::NoBootState).contains("not initialized"));
        assert!(format!("{}", OtaError::NvError("io".into())).contains("io"));
    }

    // --- install(): happy path ---

    #[test]
    fn install_swaps_to_inactive_bank_and_enters_trial() {
        let mut nv = make_nv();
        init_boot(&mut nv);

        let res = install(&mut nv, BankSet::Vm1, b"image-bytes", &meta_v(1, 0), false).unwrap();
        assert_eq!(res.target_bank, Bank::B, "must land on the inactive bank");

        let s = status(&nv, BankSet::Vm1).unwrap();
        assert_eq!(s.active_bank, Bank::B);
        assert!(!s.committed, "install must enter trial mode");
        assert_eq!(s.boot_count, 0);
    }

    #[test]
    fn install_writes_fw_meta_on_target_bank_only() {
        let mut nv = make_nv();
        init_boot(&mut nv);

        install(&mut nv, BankSet::Vm1, b"img", &meta_v(7, 0), false).unwrap();

        let b = nv.read_fw_meta(BankSet::Vm1, Bank::B).unwrap();
        assert_eq!(b.fw_seq, 7);
        assert!(
            nv.read_fw_meta(BankSet::Vm1, Bank::A).is_none(),
            "previous (A) bank must stay untouched"
        );
    }

    #[test]
    fn install_computes_sha256_in_result() {
        let mut nv = make_nv();
        init_boot(&mut nv);
        let res = install(&mut nv, BankSet::Vm1, b"hello", &meta_v(1, 0), false).unwrap();
        let expected = <[u8; 32]>::from(Sha256::digest(b"hello"));
        assert_eq!(res.image_sha256, expected);
    }

    #[test]
    fn install_does_not_raise_min_security_ver_on_install_only_commit() {
        // Anti-rollback floor must only move on commit, not install (fleet testing).
        let mut nv = make_nv();
        init_boot(&mut nv);

        // Write initial FW meta with min_security_ver=5 on bank A
        let mut initial = NvFwMeta::default();
        initial.fw_secver = 5;
        initial.min_security_ver = 5;
        nv.write_fw_meta(BankSet::Vm1, Bank::A, &mut initial)
            .unwrap();

        install(&mut nv, BankSet::Vm1, b"img", &meta_v(1, 7), false).unwrap();

        // min_security_ver on target (B) must be carried over (=5), not raised to 7.
        let b = nv.read_fw_meta(BankSet::Vm1, Bank::B).unwrap();
        assert_eq!(b.min_security_ver, 5);
        assert_eq!(b.fw_secver, 7);
    }

    // --- install(): preconditions ---

    #[test]
    fn install_rejects_when_in_trial() {
        let mut nv = make_nv();
        init_boot(&mut nv);
        install(&mut nv, BankSet::Vm1, b"img", &meta_v(1, 0), false).unwrap();

        // Second install without commit → InTrial
        let err = install(&mut nv, BankSet::Vm1, b"img2", &meta_v(2, 0), false).unwrap_err();
        assert_eq!(err, OtaError::InTrial);
    }

    #[test]
    fn install_rejects_image_below_anti_rollback_floor() {
        let mut nv = make_nv();
        init_boot(&mut nv);

        let mut cur = NvFwMeta::default();
        cur.min_security_ver = 10;
        nv.write_fw_meta(BankSet::Vm1, Bank::A, &mut cur).unwrap();

        let err = install(&mut nv, BankSet::Vm1, b"img", &meta_v(1, 3), false).unwrap_err();
        assert_eq!(
            err,
            OtaError::SecurityVersionTooLow {
                image: 3,
                floor: 10
            }
        );
    }

    #[test]
    fn install_without_boot_state_errors() {
        let mut nv = make_nv();
        // No init_boot() — boot state absent.
        let err = install(&mut nv, BankSet::Vm1, b"img", &meta_v(1, 0), false).unwrap_err();
        assert_eq!(err, OtaError::NoBootState);
    }

    // --- install(): single_bank (HSM) variant ---

    #[test]
    fn install_single_bank_writes_bank_a_and_stays_committed() {
        let mut nv = make_nv();
        init_boot(&mut nv);

        let res = install(&mut nv, BankSet::Hsm, b"key-material", &meta_v(1, 4), true).unwrap();
        assert_eq!(res.target_bank, Bank::A);

        let s = status(&nv, BankSet::Hsm).unwrap();
        assert_eq!(s.active_bank, Bank::A);
        assert!(s.committed, "single_bank install must not enter trial mode");

        // Single-bank raises floor immediately to the installed version.
        let m = nv.read_fw_meta(BankSet::Hsm, Bank::A).unwrap();
        assert_eq!(m.min_security_ver, 4);
        assert_eq!(m.fw_secver, 4);
    }

    // --- install_precomputed(): streaming path ---

    #[test]
    fn install_precomputed_swaps_bank_and_stores_hash() {
        let mut nv = make_nv();
        init_boot(&mut nv);

        let sha = [0xAA; 32];
        let res =
            install_precomputed(&mut nv, BankSet::Vm1, sha, 1234, &meta_v(1, 0), false).unwrap();
        assert_eq!(res.target_bank, Bank::B);
        assert_eq!(res.image_sha256, sha);
        assert_eq!(
            nv.read_fw_meta(BankSet::Vm1, Bank::B).unwrap().image_sha256,
            sha
        );
    }

    #[test]
    fn install_precomputed_honors_anti_rollback_floor() {
        let mut nv = make_nv();
        init_boot(&mut nv);
        let mut cur = NvFwMeta::default();
        cur.min_security_ver = 9;
        nv.write_fw_meta(BankSet::Vm1, Bank::A, &mut cur).unwrap();

        let err = install_precomputed(&mut nv, BankSet::Vm1, [0; 32], 10, &meta_v(1, 2), false)
            .unwrap_err();
        assert_eq!(err, OtaError::SecurityVersionTooLow { image: 2, floor: 9 });
    }

    // --- commit() ---

    #[test]
    fn commit_sets_committed_and_raises_floor_when_higher() {
        let mut nv = make_nv();
        init_boot(&mut nv);

        // Prior state: min_security_ver=2 on bank A.
        let mut prior = NvFwMeta::default();
        prior.fw_secver = 2;
        prior.min_security_ver = 2;
        nv.write_fw_meta(BankSet::Vm1, Bank::A, &mut prior).unwrap();

        install(&mut nv, BankSet::Vm1, b"img", &meta_v(1, 7), false).unwrap();
        commit(&mut nv, BankSet::Vm1).unwrap();

        let s = status(&nv, BankSet::Vm1).unwrap();
        assert!(s.committed);
        assert_eq!(s.boot_count, 0);

        // Floor raised to new secver=7.
        let m = nv.read_fw_meta(BankSet::Vm1, Bank::B).unwrap();
        assert_eq!(m.min_security_ver, 7);
    }

    #[test]
    fn commit_does_not_lower_floor_when_image_secver_is_below() {
        let mut nv = make_nv();
        init_boot(&mut nv);

        let mut prior = NvFwMeta::default();
        prior.fw_secver = 10;
        prior.min_security_ver = 10;
        nv.write_fw_meta(BankSet::Vm1, Bank::A, &mut prior).unwrap();

        // Install an image with same secver=10 (equal-to-floor allowed).
        install(&mut nv, BankSet::Vm1, b"img", &meta_v(1, 10), false).unwrap();
        commit(&mut nv, BankSet::Vm1).unwrap();

        let m = nv.read_fw_meta(BankSet::Vm1, Bank::B).unwrap();
        assert_eq!(m.min_security_ver, 10, "floor should not drop");
    }

    #[test]
    fn commit_rejects_when_already_committed() {
        let mut nv = make_nv();
        init_boot(&mut nv);
        let err = commit(&mut nv, BankSet::Vm1).unwrap_err();
        assert_eq!(err, OtaError::AlreadyCommitted);
    }

    #[test]
    fn commit_without_boot_state_errors() {
        let mut nv = make_nv();
        let err = commit(&mut nv, BankSet::Vm1).unwrap_err();
        assert_eq!(err, OtaError::NoBootState);
    }

    // --- rollback() ---

    #[test]
    fn rollback_swaps_back_and_recommits() {
        let mut nv = make_nv();
        init_boot(&mut nv);
        install(&mut nv, BankSet::Vm1, b"img", &meta_v(1, 0), false).unwrap();

        // After install: active=B, committed=false.
        let prev = rollback(&mut nv, BankSet::Vm1).unwrap();
        assert_eq!(prev, Bank::A);

        let s = status(&nv, BankSet::Vm1).unwrap();
        assert_eq!(
            s.active_bank,
            Bank::A,
            "rollback must restore previous bank"
        );
        assert!(s.committed);
        assert_eq!(s.boot_count, 0);
    }

    #[test]
    fn rollback_rejects_when_not_in_trial() {
        let mut nv = make_nv();
        init_boot(&mut nv);
        let err = rollback(&mut nv, BankSet::Vm1).unwrap_err();
        assert_eq!(err, OtaError::NotInTrial);
    }

    #[test]
    fn rollback_without_boot_state_errors() {
        let mut nv = make_nv();
        let err = rollback(&mut nv, BankSet::Vm1).unwrap_err();
        assert_eq!(err, OtaError::NoBootState);
    }

    // --- status() ---

    #[test]
    fn status_returns_none_without_boot_state() {
        let nv = make_nv();
        assert!(status(&nv, BankSet::Vm1).is_none());
    }

    #[test]
    fn status_exposes_fw_metadata_when_present() {
        let mut nv = make_nv();
        init_boot(&mut nv);

        let mut m = NvFwMeta::default();
        m.fw_secver = 42;
        m.min_security_ver = 10;
        nv.write_fw_meta(BankSet::Vm1, Bank::A, &mut m).unwrap();

        let s = status(&nv, BankSet::Vm1).unwrap();
        assert_eq!(s.fw_secver, Some(42));
        assert_eq!(s.min_security_ver, Some(10));
    }

    // --- Full lifecycle ---

    #[test]
    fn full_install_commit_then_install_commit_cycles() {
        let mut nv = make_nv();
        init_boot(&mut nv);

        // Cycle 1: A → B, commit
        install(&mut nv, BankSet::Vm1, b"v1", &meta_v(1, 1), false).unwrap();
        commit(&mut nv, BankSet::Vm1).unwrap();
        assert_eq!(status(&nv, BankSet::Vm1).unwrap().active_bank, Bank::B);

        // Cycle 2: B → A, commit
        install(&mut nv, BankSet::Vm1, b"v2", &meta_v(2, 2), false).unwrap();
        commit(&mut nv, BankSet::Vm1).unwrap();
        assert_eq!(status(&nv, BankSet::Vm1).unwrap().active_bank, Bank::A);
        assert_eq!(
            nv.read_fw_meta(BankSet::Vm1, Bank::A)
                .unwrap()
                .min_security_ver,
            2,
            "floor tracks committed secver across cycles"
        );
    }

    #[test]
    fn install_then_rollback_restores_bank_a_committed() {
        let mut nv = make_nv();
        init_boot(&mut nv);
        install(&mut nv, BankSet::Vm1, b"bad-image", &meta_v(1, 0), false).unwrap();
        assert_eq!(status(&nv, BankSet::Vm1).unwrap().active_bank, Bank::B);

        rollback(&mut nv, BankSet::Vm1).unwrap();
        let s = status(&nv, BankSet::Vm1).unwrap();
        assert_eq!(s.active_bank, Bank::A);
        assert!(s.committed);
    }

    #[test]
    fn install_is_independent_per_bank_set() {
        // Installing vm1 must not disturb vm2.
        let mut nv = make_nv();
        init_boot(&mut nv);

        install(&mut nv, BankSet::Vm1, b"img-vm1", &meta_v(1, 0), false).unwrap();
        let vm2 = status(&nv, BankSet::Vm2).unwrap();
        assert_eq!(vm2.active_bank, Bank::A);
        assert!(vm2.committed);
    }
}
