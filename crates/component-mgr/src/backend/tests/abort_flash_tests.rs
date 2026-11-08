//! `DiagnosticBackend::abort_flash` on the directly-wired engine
//! (bank/hsm). Restores the pre-convergence semantics the round-trip
//! `ComponentAdapter::abort_install` used to provide: Ok pre-finalize,
//! refusal post-finalize. The routed (vm2/app) abort path is covered in
//! `install_router_diag_tests`.
use super::super::*;
use crate::manifest_provider::ManifestError;
use nv_store::block::MemBlockDevice;
use nv_store::slots;
use nv_store::store::MIN_NV_DEVICE_SIZE;

struct NoopManifest;
impl ManifestProvider for NoopManifest {
    fn validate(&self, _d: &[u8], _m: u32) -> Result<ValidatedFirmware, ManifestError> {
        Err(ManifestError::ParseError("unused".into()))
    }
}

fn backend() -> ComponentBackend<MemBlockDevice> {
    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    nv.write_boot_state(&mut boot).unwrap();
    ComponentBackend::with_options(
        slots::VM1,
        Arc::new(Mutex::new(nv)),
        Arc::new(NoopManifest),
        ComponentConfig::default(),
        None,
        None,
        None,
    )
}

/// Seed a flash transfer in `state` so `flash_is_finalized()` reflects it.
fn set_transfer_state(b: &ComponentBackend<MemBlockDevice>, state: FlashState) {
    *b.flash_transfer.lock().unwrap() = Some(FlashTransferState {
        transfer_id: "t1".into(),
        package_id: "pkg-1".into(),
        state,
        pre_reset_health: None,
        image_size: 0,
        streamed_files: Vec::new(),
    });
}

#[tokio::test]
async fn abort_flash_ok_when_no_session() {
    // No session in flight — abort is an idempotent success (mirrors
    // ComponentAdapter::abort_install on a fresh backend).
    let b = backend();
    assert!(!b.flash_is_finalized());
    b.abort_flash("nope").await.unwrap();
}

#[tokio::test]
async fn abort_flash_ok_pre_finalize_clears_session() {
    // A staged-but-not-finalized session (AwaitingActivation) aborts Ok and
    // the staging state is dropped.
    let b = backend();
    *b.flash_session.lock().unwrap() = Some(FlashSessionState::Complete);
    set_transfer_state(&b, FlashState::AwaitingActivation);
    assert!(!b.flash_is_finalized());

    b.abort_flash("t1").await.unwrap();

    assert!(b.flash_session.lock().unwrap().is_none());
    assert!(b.flash_transfer.lock().unwrap().is_none());
}

#[tokio::test]
async fn abort_flash_rejected_post_finalize() {
    // Post-finalize (bank pointer already flipped) abort must refuse — the
    // engine can't unflip it. Surfaced as InvalidRequest (HTTP 400), the
    // exact wire mapping `map_machine_error` produces from the adapter's
    // PolicyRejected, so direct and routed abort paths agree.
    for st in [
        FlashState::AwaitingReboot,
        FlashState::Activated,
        FlashState::Committed,
        FlashState::RolledBack,
    ] {
        let b = backend();
        set_transfer_state(&b, st);
        assert!(b.flash_is_finalized(), "{st:?} should be finalized");

        let err = b.abort_flash("t1").await.unwrap_err();
        assert!(
            matches!(err, BackendError::InvalidRequest(_)),
            "{st:?}: expected InvalidRequest, got {err:?}"
        );
        assert_eq!(err.status_code(), 400, "{st:?}");
        // Refused → the finalized transfer is left intact, not cleared.
        assert!(b.flash_transfer.lock().unwrap().is_some(), "{st:?}");
    }
}

/// Abort with a session in flight keeps the verified parts the target
/// bank holds and their staging record, and only forgets the update id:
/// the record is a part cache now, not a held update. (A torn upload
/// never reaches the bank — it stages beside it and goes at the next
/// manifest.)
#[tokio::test]
async fn abort_session_keeps_staged_parts_and_forgets_the_update_id() {
    let dir = tempfile::tempdir().unwrap();
    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    boot.banks[slots::VM1.as_index()].active_bank = Bank::A;
    nv.write_boot_state(&mut boot).unwrap();
    let b = ComponentBackend::with_options(
        slots::VM1,
        Arc::new(Mutex::new(nv)),
        Arc::new(NoopManifest),
        ComponentConfig::default(),
        None,
        Some(dir.path().to_path_buf()),
        None,
    )
    .with_bank_spec(crate::bank_spec::BankSetSpec {
        dir_name: "vm1".into(),
    });
    // Active = A ⇒ target = B. Stage a verified part in bank_b.
    let bank_b = dir.path().join("vm1").join("bank_b");
    std::fs::create_dir_all(&bank_b).unwrap();
    std::fs::write(bank_b.join("rootfs.img"), vec![0u8; 1024]).unwrap();
    b.set_update_id(Some("upd-1".into()));
    let part = hsm::ivd::IvdFile {
        relative_path: "rootfs.img".into(),
        sha256: vec![7u8; 32],
        size: 1024,
    };
    b.record_staged_part(Bank::B, &part).unwrap();
    let before = b.bank_provider.staging_record(Bank::B).unwrap().unwrap();
    assert_eq!(before.update_id.as_deref(), Some("upd-1"));

    *b.flash_session.lock().unwrap() = Some(FlashSessionState::Complete);
    b.abort_session().unwrap();

    assert!(b.flash_session.lock().unwrap().is_none());
    assert!(
        bank_b.join("rootfs.img").exists(),
        "abort keeps the staged part in the target bank"
    );
    let after = b.bank_provider.staging_record(Bank::B).unwrap().unwrap();
    assert_eq!(after.update_id, None, "abort forgets the update id");
    assert_eq!(after.parts, before.parts, "…and keeps the parts");
    assert_eq!(*b.update_id.lock().unwrap(), None);
}

/// Abort with NO session in flight must NOT touch the target bank — with
/// nothing staged, `target_bank()` is just the next install's destination
/// (and for single-bank components it IS the live bank). A stale wire
/// DELETE arrives as a no-op, not a wipe.
#[tokio::test]
async fn abort_session_without_session_leaves_banks_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    boot.banks[slots::VM1.as_index()].active_bank = Bank::A;
    nv.write_boot_state(&mut boot).unwrap();
    let b = ComponentBackend::with_options(
        slots::VM1,
        Arc::new(Mutex::new(nv)),
        Arc::new(NoopManifest),
        ComponentConfig::default(),
        None,
        Some(dir.path().to_path_buf()),
        None,
    )
    .with_bank_spec(crate::bank_spec::BankSetSpec {
        dir_name: "vm1".into(),
    });
    let bank_b = dir.path().join("vm1").join("bank_b");
    std::fs::create_dir_all(&bank_b).unwrap();
    std::fs::write(bank_b.join("rootfs.img"), vec![0u8; 1024]).unwrap();

    b.abort_session().unwrap();

    assert!(
        bank_b.join("rootfs.img").exists(),
        "abort with no session in flight must not wipe the target bank"
    );
}
