//! Provider-level integration tests for `bank_seed::seed_missing_files`
//! wired through `IvdBankProvider::seed_target_from_active`.
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
//!
//! The production seed runs inside `IvdBankProvider::seal`; these tests
//! exercise the same primitive directly on the provider (the engine no
//! longer holds a concrete `IvdBankProvider`, only `Arc<dyn BankProvider>`).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use nv_store::block::MemBlockDevice;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::*;

use component_mgr::backend::ComponentConfig;
use component_mgr::bank_provider::IvdBankProvider;
use component_mgr::bank_spec::BankSetSpec;

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

/// Build an `IvdBankProvider` with the same nv / bank_set / images_dir /
/// dir_name the backend would, so `seed_target_from_active` resolves the
/// active bank from NV and composes identical on-disk paths.
fn make_backend(
    nv: Arc<Mutex<NvStore<MemBlockDevice>>>,
    set: BankSet,
    config: ComponentConfig,
    images_dir: Option<PathBuf>,
) -> IvdBankProvider<MemBlockDevice> {
    let dir_name = BankSetSpec::for_well_known(set).dir_name;
    IvdBankProvider::new(
        nv,
        set,
        config.single_bank,
        images_dir,
        dir_name,
        None,
        None,
        None,
    )
}

fn write_file(p: &std::path::Path, content: &[u8]) {
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(p, content).unwrap();
}

/// The part list the manifest being sealed declares — what the engine hands
/// `seal` from the flash transfer's inventory.
fn declared(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// Canonical partial-update case: vm1 bank's active = A, contains a
/// full bank. A flash declaring four parts arrives streaming only
/// `policy.sqfs` into bank_b. After seed_target_from_active(B), bank_b
/// should have the streamed policy.sqfs PLUS kernel + rootfs.img +
/// vm-config.yaml reused from bank_a.
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

    backend
        .seed_target_from_active(
            Bank::B,
            &declared(&["kernel", "rootfs.img", "vm-config.yaml", "policy.sqfs"]),
        )
        .expect("seed runs");

    // Streamed file preserved.
    assert_eq!(
        std::fs::read(target_dir.join("policy.sqfs")).unwrap(),
        b"NEW policy image",
    );
    // Unstreamed files seeded from active.
    assert_eq!(
        std::fs::read(target_dir.join("kernel")).unwrap(),
        b"old kernel"
    );
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

    backend
        .seed_target_from_active(
            Bank::B,
            &declared(&["kernel", "rootfs.img", "vm-config.yaml", "policy.sqfs"]),
        )
        .expect("seed runs");

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

    backend
        .seed_target_from_active(Bank::B, &declared(&["policy.sqfs"]))
        .expect("seed runs");
    assert_eq!(
        std::fs::read(target_dir.join("policy.sqfs")).unwrap(),
        b"new"
    );
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
    backend
        .seed_target_from_active(Bank::A, &declared(&["manifest.cbor"]))
        .expect("seed runs");

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
        .seed_target_from_active(Bank::B, &declared(&["kernel"]))
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
    backend
        .seed_target_from_active(Bank::A, &declared(&["kernel"]))
        .expect("noop");

    // Source unchanged (would still be "running kernel" either way,
    // but we're confirming it didn't get a recursive copy).
    assert_eq!(
        std::fs::read(active_dir.join("kernel")).unwrap(),
        b"running kernel"
    );
}

/// A declared part may live in a subdirectory of the bank — seed
/// creates the parent dirs on the way (covers the case where a bank
/// component is a tree of files rather than a single image).
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
    backend
        .seed_target_from_active(
            Bank::B,
            &declared(&["kernel", "policy/policy.yaml", "policy/roots/sumo-sign.pem"]),
        )
        .expect("seed");

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

/// The field failure, at provider level: a cross-channel vm1 flash
/// (cicd → skan8f) ships every part its manifest declares into bank_a
/// while the RUNNING bank_b still holds cicd-only images the guest has
/// open through devb-loopback. Seed must copy nothing — and must not go
/// near the undeclared images, whose open is what raised EBUSY and
/// failed the seal with `bank seed from …/bank_b to …/bank_a: Resource
/// busy`.
#[test]
fn cross_channel_flash_leaves_undeclared_active_files_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let images_dir = tmp.path().to_path_buf();
    let nv = make_nv();
    // The device is running bank_b; the flash targets bank_a.
    set_active_bank(&nv, BankSet::Vm1, Bank::B);

    let active_dir = images_dir.join("vm1/bank_b");
    write_file(&active_dir.join("kernel"), b"cicd kernel");
    write_file(&active_dir.join("rootfs.img"), b"cicd rootfs");
    write_file(&active_dir.join("rt-link"), b"cicd-only image");
    write_file(&active_dir.join("diagnostics"), b"cicd-only image");

    // The skan8f manifest declares two parts and streamed both.
    let target_dir = images_dir.join("vm1/bank_a");
    write_file(&target_dir.join("kernel"), b"skan8f kernel");
    write_file(&target_dir.join("rootfs.img"), b"skan8f rootfs");

    let backend = make_backend(
        nv,
        BankSet::Vm1,
        ComponentConfig::default(),
        Some(images_dir.clone()),
    );

    backend
        .seed_target_from_active(Bank::A, &declared(&["kernel", "rootfs.img"]))
        .expect("a fully-shipped manifest seeds nothing and cannot fail");

    for name in ["rt-link", "diagnostics"] {
        assert!(
            !target_dir.join(name).exists(),
            "{name} is outside this manifest — it must never be copied into the target bank",
        );
    }
    assert_eq!(
        std::fs::read(target_dir.join("kernel")).unwrap(),
        b"skan8f kernel",
        "the streamed part must keep its bytes",
    );
}
