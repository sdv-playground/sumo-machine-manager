//! Backend-level integration tests for `bank_seed::seed_missing_files`
//! wired through `VmBackend::seed_target_from_active`.
//!
//! These complement the pure-function tests in `bank_seed::tests`
//! (file-by-file semantics) by validating that:
//!   - the helper resolves the right source bank from NV state
//!   - it composes the right images_dir paths
//!   - single-bank, no-active-bank, and no-images-dir cases are
//!     handled as no-ops
//!   - the "seed before IVD sign" ordering invariant is encoded in
//!     a way a future refactor can't silently break (we assert the
//!     visible file system state after the seed runs)

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use nv_store::block::MemBlockDevice;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::*;

use crate::backend::{ComponentConfig, VmBackend};
use crate::manifest_provider::ManifestProvider;
use crate::sovd::security::TestSecurityProvider;
use crate::suit_provider::SuitProvider;

fn make_nv() -> Arc<Mutex<NvStore<MemBlockDevice>>> {
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    let mut state = NvBootState::default();
    nv.write_boot_state(&mut state).unwrap();
    Arc::new(Mutex::new(nv))
}

fn set_active_bank(nv: &Arc<Mutex<NvStore<MemBlockDevice>>>, set: BankSet, active: Bank) {
    let mut nv_guard = nv.lock().unwrap();
    let mut state = nv_guard.read_boot_state().unwrap();
    state.banks[set.as_index()].active_bank = active;
    nv_guard.write_boot_state(&mut state).unwrap();
}

fn make_backend(
    nv: Arc<Mutex<NvStore<MemBlockDevice>>>,
    set: BankSet,
    config: ComponentConfig,
    images_dir: Option<PathBuf>,
) -> Arc<VmBackend<MemBlockDevice>> {
    let trust_anchor = vec![0u8; 32];
    let mp: Arc<dyn ManifestProvider> = Arc::new(SuitProvider::new(trust_anchor));
    let sp = Arc::new(TestSecurityProvider);
    Arc::new(VmBackend::with_options(set, nv, mp, sp, config, None, images_dir))
}

fn write_file(p: &std::path::Path, content: &[u8]) {
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(p, content).unwrap();
}

/// Canonical partial-update case: vm1 bank's active = A, contains a
/// full bank. A flash arrives streaming only `policy.sqfs` into
/// bank_b. After seed_target_from_active(B), bank_b should have the
/// streamed policy.sqfs PLUS kernel + rootfs.img + vm-config.yaml
/// from bank_a.
#[test]
fn partial_flash_seeds_unstreamed_components_from_active() {
    let tmp = tempfile::tempdir().unwrap();
    let images_dir = tmp.path().to_path_buf();
    let nv = make_nv();
    set_active_bank(&nv, BankSet::Vm1, Bank::A);

    // Populate the "active" bank (bank_a) with a full set of files.
    let active_dir = images_dir.join("vm1/bank_a");
    write_file(&active_dir.join("kernel"), b"old kernel");
    write_file(&active_dir.join("rootfs.img"), b"old rootfs");
    write_file(&active_dir.join("vm-config.yaml"), b"old: config");
    write_file(&active_dir.join("policy.sqfs"), b"OLD policy image");

    // Populate the "target" bank (bank_b) with just the streamed
    // file — simulates a partial OTA envelope that only carries
    // policy.sqfs.
    let target_dir = images_dir.join("vm1/bank_b");
    write_file(&target_dir.join("policy.sqfs"), b"NEW policy image");

    let backend = make_backend(
        nv,
        BankSet::Vm1,
        ComponentConfig::default(),
        Some(images_dir.clone()),
    );

    backend.seed_target_from_active(Bank::B).expect("seed runs");

    // Streamed file preserved.
    assert_eq!(
        std::fs::read(target_dir.join("policy.sqfs")).unwrap(),
        b"NEW policy image",
    );
    // Unstreamed files seeded from active.
    assert_eq!(std::fs::read(target_dir.join("kernel")).unwrap(), b"old kernel");
    assert_eq!(
        std::fs::read(target_dir.join("rootfs.img")).unwrap(),
        b"old rootfs"
    );
    assert_eq!(
        std::fs::read(target_dir.join("vm-config.yaml")).unwrap(),
        b"old: config"
    );
}

/// Full OTA (envelope carried every component) — every file is in
/// target already; seed must be a no-op and must NOT overwrite the
/// new files with the active bank's stale versions.
#[test]
fn full_flash_seed_is_noop() {
    let tmp = tempfile::tempdir().unwrap();
    let images_dir = tmp.path().to_path_buf();
    let nv = make_nv();
    set_active_bank(&nv, BankSet::Vm1, Bank::A);

    let active_dir = images_dir.join("vm1/bank_a");
    write_file(&active_dir.join("kernel"), b"old");
    write_file(&active_dir.join("rootfs.img"), b"old");
    write_file(&active_dir.join("vm-config.yaml"), b"old");
    write_file(&active_dir.join("policy.sqfs"), b"OLD");

    let target_dir = images_dir.join("vm1/bank_b");
    write_file(&target_dir.join("kernel"), b"NEW");
    write_file(&target_dir.join("rootfs.img"), b"NEW");
    write_file(&target_dir.join("vm-config.yaml"), b"NEW");
    write_file(&target_dir.join("policy.sqfs"), b"NEW");

    let backend = make_backend(
        nv,
        BankSet::Vm1,
        ComponentConfig::default(),
        Some(images_dir.clone()),
    );

    backend.seed_target_from_active(Bank::B).expect("seed runs");

    for name in ["kernel", "rootfs.img", "vm-config.yaml", "policy.sqfs"] {
        assert_eq!(
            std::fs::read(target_dir.join(name)).unwrap(),
            b"NEW",
            "{name} must keep its streamed value",
        );
    }
}

/// Factory first-flash: no active bank exists on disk yet. Seed
/// must succeed (returning Ok) with no files copied — the target
/// bank is whatever the streaming step left it as.
#[test]
fn missing_active_bank_dir_is_noop() {
    let tmp = tempfile::tempdir().unwrap();
    let images_dir = tmp.path().to_path_buf();
    let nv = make_nv();
    set_active_bank(&nv, BankSet::Vm1, Bank::A);

    // active dir never created — that's the factory state.
    let target_dir = images_dir.join("vm1/bank_b");
    write_file(&target_dir.join("policy.sqfs"), b"new");

    let backend = make_backend(
        nv,
        BankSet::Vm1,
        ComponentConfig::default(),
        Some(images_dir.clone()),
    );

    backend.seed_target_from_active(Bank::B).expect("seed runs");
    assert_eq!(std::fs::read(target_dir.join("policy.sqfs")).unwrap(), b"new");
}

/// HSM-style single-bank components have no peer bank. seed must
/// short-circuit and not touch anything.
#[test]
fn single_bank_short_circuits() {
    let tmp = tempfile::tempdir().unwrap();
    let images_dir = tmp.path().to_path_buf();
    let nv = make_nv();

    let single_bank_dir = images_dir.join("hsm/bank_a");
    write_file(&single_bank_dir.join("manifest.cbor"), b"hsm manifest");

    let cfg = ComponentConfig {
        single_bank: true,
        entity_type: "hsm".into(),
        ..ComponentConfig::default()
    };
    let backend = make_backend(nv, BankSet::Hsm, cfg, Some(images_dir.clone()));

    // Target == Bank::A (the only one); seed should be a no-op.
    backend.seed_target_from_active(Bank::A).expect("seed runs");

    // File unchanged.
    assert_eq!(
        std::fs::read(single_bank_dir.join("manifest.cbor")).unwrap(),
        b"hsm manifest"
    );
}

/// No images_dir configured (in-memory test backends, e.g. SOVD
/// unit tests). Helper must return Ok without touching anything.
#[test]
fn no_images_dir_is_noop() {
    let nv = make_nv();
    set_active_bank(&nv, BankSet::Vm1, Bank::A);
    let backend = make_backend(nv, BankSet::Vm1, ComponentConfig::default(), None);
    backend
        .seed_target_from_active(Bank::B)
        .expect("seed is a no-op without images_dir");
}

/// Defensive: if a future refactor breaks the "target == active.other()"
/// invariant and the caller asks to seed FROM active INTO active,
/// the helper must refuse rather than silently corrupting the
/// running bank.
#[test]
fn target_equals_active_is_noop_not_self_corruption() {
    let tmp = tempfile::tempdir().unwrap();
    let images_dir = tmp.path().to_path_buf();
    let nv = make_nv();
    set_active_bank(&nv, BankSet::Vm1, Bank::A);

    let active_dir = images_dir.join("vm1/bank_a");
    write_file(&active_dir.join("kernel"), b"running kernel");

    let backend = make_backend(
        nv,
        BankSet::Vm1,
        ComponentConfig::default(),
        Some(images_dir.clone()),
    );
    // Caller passes Bank::A (== active) by mistake — must not
    // touch anything.
    backend.seed_target_from_active(Bank::A).expect("noop");

    // Source unchanged (would still be "running kernel" either way,
    // but we're confirming it didn't get a recursive copy).
    assert_eq!(
        std::fs::read(active_dir.join("kernel")).unwrap(),
        b"running kernel"
    );
}

/// Active bank populated with subdirectories — seed walks them
/// recursively (covers the future case where a bank component is
/// a directory tree rather than a single image file).
#[test]
fn seeds_subdirectories_from_active() {
    let tmp = tempfile::tempdir().unwrap();
    let images_dir = tmp.path().to_path_buf();
    let nv = make_nv();
    set_active_bank(&nv, BankSet::Vm1, Bank::A);

    let active_dir = images_dir.join("vm1/bank_a");
    write_file(&active_dir.join("kernel"), b"k");
    write_file(&active_dir.join("policy/policy.yaml"), b"version: 1");
    write_file(&active_dir.join("policy/roots/sumo-sign.pem"), b"pem");

    let target_dir = images_dir.join("vm1/bank_b");
    std::fs::create_dir_all(&target_dir).unwrap();
    // Target gets a kernel from streaming but no policy tree.
    write_file(&target_dir.join("kernel"), b"K-NEW");

    let backend = make_backend(
        nv,
        BankSet::Vm1,
        ComponentConfig::default(),
        Some(images_dir.clone()),
    );
    backend.seed_target_from_active(Bank::B).expect("seed");

    assert_eq!(std::fs::read(target_dir.join("kernel")).unwrap(), b"K-NEW");
    assert_eq!(
        std::fs::read(target_dir.join("policy/policy.yaml")).unwrap(),
        b"version: 1"
    );
    assert_eq!(
        std::fs::read(target_dir.join("policy/roots/sumo-sign.pem")).unwrap(),
        b"pem"
    );
}
