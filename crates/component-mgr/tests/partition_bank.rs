//! Integration test: `PartitionBankProvider` driven end-to-end through
//! `ComponentBackend` — a raw-partition bank with three declared parts
//! installs a three-payload SUIT manifest with every byte landing on its own
//! device and a signed IVD attesting exactly those parts; a manifest naming
//! an undeclared fourth part is refused with HTTP 415 at manifest time,
//! before any device is touched.
//!
//! The provider/HSM construction mirrors
//! `partition_bank_provider::tests::build_with` (an integration test can't
//! reach that module's private `super::` helpers, so the minimal subset is
//! reproduced here); the backend-driving style mirrors
//! `backend::declared_parts_tests`, but through the public
//! `DiagnosticBackend::{start_flash, receive_package_stream}` wire instead of
//! the crate-internal `handle_manifest_upload` / `handle_payload_upload`.
//!
//! "Device" = a plain temp file. `PartitionPart::partition_a` / `partition_b`
//! are just paths — production points them at real block devices (e.g.
//! `/dev/blk0p1`), but nothing here depends on that.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use sha2::{Digest, Sha256};

use nv_store::block::MemBlockDevice;
use nv_store::slots;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::{Bank, NvBootState};

use machine_mgr::bank_provider::BankProvider;
use sovd_core::{BackendError, DiagnosticBackend, PackageStream};

use component_mgr::backend::{ComponentBackend, ComponentConfig};
use component_mgr::bank_provider::{bank_dir_name, IvdBankProvider};
use component_mgr::bank_spec::BankSetSpec;
use component_mgr::partition_bank_provider::{PartitionBankProvider, PartitionPart};
use component_mgr::suit_provider::SuitProvider;

use sumo_offboard::cose_key::CoseKey;
use sumo_offboard::image_builder::{ComponentSpec as SuitComponentSpec, MultiComponentBuilder};
use sumo_offboard::keygen;

/// The three parts this bank declares: wire name, payload size, fill byte
/// (a distinct pattern per part so a misrouted write is unmistakable).
const PARTS: [(&str, usize, u8); 3] = [
    ("application.img", 4096, 0xAA),
    ("ifs", 8192, 0xBB),
    ("rootfs", 12288, 0xCC),
];

/// One declared part: its payload and its two "devices" — temp files
/// pre-sized to the payload length. `seal` hashes a device to EOF, so a
/// device's size must equal its payload's size for the read-back verify to
/// match (mirrors `partition_bank_provider`'s own unit tests).
struct PartFixture {
    name: &'static str,
    payload: Vec<u8>,
    dev_a: PathBuf,
    dev_b: PathBuf,
}

impl PartFixture {
    fn device(&self, bank: Bank) -> &Path {
        match bank {
            Bank::A => &self.dev_a,
            Bank::B => &self.dev_b,
        }
    }
}

fn make_parts(tmp: &Path) -> Vec<PartFixture> {
    PARTS
        .iter()
        .map(|&(name, size, fill)| {
            let dev_a = tmp.join(format!("{name}-a.dev"));
            let dev_b = tmp.join(format!("{name}-b.dev"));
            std::fs::write(&dev_a, vec![0u8; size]).unwrap();
            std::fs::write(&dev_b, vec![0u8; size]).unwrap();
            PartFixture {
                name,
                payload: vec![fill; size],
                dev_a,
                dev_b,
            }
        })
        .collect()
}

/// Provision the IVD-signing slot in a fresh keystore dir. Reproduces
/// `partition_bank_provider::tests::provisioned_keystore`.
fn provisioned_keystore(tmp: &Path) -> PathBuf {
    use hsm::payload::*;
    let ks_dir = tmp.join("keystore");
    std::fs::create_dir_all(&ks_dir).unwrap();
    let hsm = hsm_sim_backend::SimHsm::new(ks_dir.clone());
    hsm.write_keystore(&HsmKeystore {
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
    })
    .unwrap();
    std::fs::write(ks_dir.join("provision_state"), b"1\n").unwrap();
    ks_dir
}

/// Handles shared between the raw-partition provider and the `host` backend
/// it's injected into: the provider (as `Arc<dyn BankProvider>`, so the test
/// can call it directly for assertions), the NV store it reads/writes, and
/// the crypto handle for the backend's own `with_hsm_crypto`.
type ProviderHandles = (
    Arc<dyn BankProvider>,
    Arc<Mutex<NvStore<MemBlockDevice>>>,
    Arc<dyn hsm::HsmCryptoProvider>,
);

/// Build the raw-partition `PartitionBankProvider` (as `Arc<dyn BankProvider>`
/// so both the backend and the test's own assertions share one handle) over a
/// fresh NV store and a provisioned SimHsm keystore. Mirrors
/// `partition_bank_provider::tests::build_with`: `bank_activator = None` (so
/// `activate()` is the selector-flip only) and no selector (NV-only
/// fallback), dir name `"os"`.
fn partition_provider(tmp: &Path, parts: &[PartFixture]) -> ProviderHandles {
    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    nv.write_boot_state(&mut NvBootState::default()).unwrap();
    let nv = Arc::new(Mutex::new(nv));

    let ks = provisioned_keystore(tmp);
    let hsm: Arc<Mutex<dyn hsm::HsmProvider>> =
        Arc::new(Mutex::new(hsm_sim_backend::SimHsm::new(ks.clone())));
    let crypto: Arc<dyn hsm::HsmCryptoProvider> = Arc::new(hsm_sim_backend::SimHsm::new(ks));

    let inner = IvdBankProvider::new(
        nv.clone(),
        slots::OS,
        false,
        Some(tmp.join("images")),
        "os".into(),
        Some(hsm.clone()),
        None, // bank_activator: activate() is the selector-flip only
        None, // selector: NV-only fallback
    )
    .with_hsm_crypto(crypto.clone());

    let partition_parts = parts
        .iter()
        .map(|p| PartitionPart {
            file: p.name.to_string(),
            partition_a: p.dev_a.to_string_lossy().into_owned(),
            partition_b: p.dev_b.to_string_lossy().into_owned(),
            record: None,
        })
        .collect();

    let provider: Arc<dyn BankProvider> = Arc::new(PartitionBankProvider::new(
        inner,
        partition_parts,
        Some(hsm),
        Some(crypto.clone()),
    ));

    (provider, nv, crypto)
}

/// Build the `host` `ComponentBackend` over `provider`, declaring exactly
/// `declared` as the parts its bank holds and trusting `signing_pubkey` as
/// the SUIT software authority.
fn host_backend(
    provider: Arc<dyn BankProvider>,
    nv: Arc<Mutex<NvStore<MemBlockDevice>>>,
    crypto: Arc<dyn hsm::HsmCryptoProvider>,
    declared: &[&str],
    signing_pubkey: Vec<u8>,
) -> ComponentBackend<MemBlockDevice> {
    let suit_provider = SuitProvider::new(signing_pubkey.clone());
    suit_provider.update_keys(signing_pubkey, None, None);

    ComponentBackend::with_options(
        slots::OS,
        nv,
        Arc::new(suit_provider),
        ComponentConfig::default(),
        None,
        None,
        None,
    )
    .with_id("host".into())
    .with_bank_spec(BankSetSpec {
        dir_name: "os".into(),
    })
    .with_hsm_crypto(crypto)
    .with_bank_provider(provider)
    .with_declared_parts(declared.iter().map(|s| s.to_string()))
}

fn stream_of(data: Vec<u8>) -> PackageStream {
    Box::pin(futures::stream::iter(vec![Ok::<
        Bytes,
        Box<dyn std::error::Error + Send + Sync>,
    >(Bytes::from(data))]))
}

/// A detached multi-component manifest addressed to `host`, signed with
/// `key` — one component per `(part_name, payload)`, digest + size computed
/// from the real payload bytes.
fn signed_manifest(key: &CoseKey, parts: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = MultiComponentBuilder::new()
        .signing_time(1_700_000_000)
        .sequence_number(1);
    for &(name, payload) in parts {
        builder = builder.add_component(SuitComponentSpec {
            id: vec!["host".into(), name.into()],
            digest: Sha256::digest(payload).to_vec(),
            size: payload.len() as u64,
            uri: format!("#{name}"),
            encryption_info: None,
        });
    }
    builder.build(key).unwrap()
}

/// Every regular file under `dir`, recursively; empty (never an error) when
/// `dir` doesn't exist. `start_flash` creates the target bank dir up front
/// (empty), so "no FILE appeared" is the meaningful assertion, not "no
/// directory".
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(files_under(&path));
        } else {
            out.push(path);
        }
    }
    out
}

#[tokio::test]
async fn three_part_install_lands_every_part_on_its_device_and_the_ivd_lists_exactly_them() {
    let tmp = tempfile::tempdir().unwrap();
    let parts = make_parts(tmp.path());
    let (provider, nv, crypto) = partition_provider(tmp.path(), &parts);

    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let backend = host_backend(
        provider.clone(),
        nv,
        crypto,
        &["application.img", "ifs", "rootfs"],
        key.public_key_bytes(),
    );

    let manifest_parts: Vec<(&str, &[u8])> = parts
        .iter()
        .map(|p| (p.name, p.payload.as_slice()))
        .collect();
    let manifest = signed_manifest(&key, &manifest_parts);

    backend.start_flash().await.expect("flash session starts");
    backend
        .receive_package_stream(stream_of(manifest), None)
        .await
        .expect("manifest accepted — every part is declared");
    for part in &parts {
        backend
            .receive_package_stream(stream_of(part.payload.clone()), None)
            .await
            .unwrap_or_else(|e| panic!("{}: payload upload rejected: {e:?}", part.name));
    }

    let target = provider.target_bank();
    let active = provider.active_bank();
    assert_ne!(
        target, active,
        "install must target the sibling of the active bank"
    );

    for part in &parts {
        assert_eq!(
            std::fs::read(part.device(target)).unwrap(),
            part.payload,
            "{}: target device holds exactly the uploaded bytes",
            part.name
        );
        assert_eq!(
            std::fs::read(part.device(active)).unwrap(),
            vec![0u8; part.payload.len()],
            "{}: the active bank's device is untouched",
            part.name
        );
    }

    // The signed IVD lists exactly the three declared parts, in declared
    // (== upload) order.
    let installed = provider.read_installed(target).expect("bank sealed");
    let names: Vec<&str> = installed.files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        names,
        ["application.img", "ifs", "rootfs"],
        "the IVD lists exactly the three declared parts, in declared order"
    );
    assert!(installed.signature.is_some(), "the IVD carries a signature");
    assert!(installed.raw.is_some(), "the IVD carries its signed bytes");

    // The metadata dir holds ONLY the IVD manifest + signature — the sink IS
    // the partition, so no staged payload file ever lands here.
    let metadata_dir = tmp
        .path()
        .join("images")
        .join("os")
        .join(bank_dir_name(target));
    let mut entries: Vec<String> = std::fs::read_dir(&metadata_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();
    let mut expected = vec![
        hsm::ivd::IVD_MANIFEST_FILE.to_string(),
        hsm::ivd::IVD_SIGNATURE_FILE.to_string(),
    ];
    expected.sort();
    assert_eq!(
        entries, expected,
        "the metadata dir holds ONLY the IVD manifest + signature — no staged payload files"
    );
}

#[tokio::test]
async fn a_manifest_naming_an_undeclared_part_is_refused_at_manifest_time() {
    let tmp = tempfile::tempdir().unwrap();
    let parts = make_parts(tmp.path());
    let (provider, nv, crypto) = partition_provider(tmp.path(), &parts);

    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let backend = host_backend(
        provider,
        nv,
        crypto,
        &["application.img", "ifs", "rootfs"],
        key.public_key_bytes(),
    );

    // Four components — the undeclared "kernel" placed FIRST, so even the
    // very first part the manifest-time check inspects is already bad.
    let kernel_payload = b"not a declared part".to_vec();
    let mut bad_parts: Vec<(&str, &[u8])> = vec![("kernel", kernel_payload.as_slice())];
    bad_parts.extend(parts.iter().map(|p| (p.name, p.payload.as_slice())));
    let bad_manifest = signed_manifest(&key, &bad_parts);

    backend.start_flash().await.expect("flash session starts");
    let err = backend
        .receive_package_stream(stream_of(bad_manifest), None)
        .await
        .expect_err("a manifest naming an undeclared part must be refused");
    assert_eq!(err.status_code(), 415, "got {err:?}");
    assert!(
        matches!(&err, BackendError::UnsupportedMediaType(m) if m.contains("kernel")),
        "the refusal names the undeclared part: {err:?}"
    );

    // Nothing touched: every device (both banks) is still all-zero, and no
    // file appeared anywhere under images_dir/ from the refused manifest.
    for part in &parts {
        assert_eq!(
            std::fs::read(&part.dev_a).unwrap(),
            vec![0u8; part.payload.len()],
            "{}: bank A device untouched",
            part.name
        );
        assert_eq!(
            std::fs::read(&part.dev_b).unwrap(),
            vec![0u8; part.payload.len()],
            "{}: bank B device untouched",
            part.name
        );
    }
    assert!(
        files_under(&tmp.path().join("images")).is_empty(),
        "no file appeared under images_dir/ from the refused manifest"
    );

    // The same session accepts a corrected manifest naming only declared
    // parts — the refusal moved nothing.
    let good_parts: Vec<(&str, &[u8])> = parts
        .iter()
        .map(|p| (p.name, p.payload.as_slice()))
        .collect();
    let good_manifest = signed_manifest(&key, &good_parts);
    backend
        .receive_package_stream(stream_of(good_manifest), None)
        .await
        .expect("a manifest within the declared parts is accepted");
}
