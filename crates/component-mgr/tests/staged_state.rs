//! Integration test: a half-staged update survives a machine-manager restart
//! as facts the node can prove. A file bank driven through `ComponentBackend`
//! keeps the parts its staging record names (re-verified by digest) across a
//! new backend over the same dir, takes parts by content in any order, refuses
//! a payload that is no part of the manifest, and seals the update id into the
//! bank. A partition bank keeps its record the same way. Parts named by the
//! client land as that part under its digest, and `held_updates` reads the
//! update the bank holds from the same facts.
//!
//! The provider/HSM/manifest construction mirrors `tests/partition_bank.rs`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use sha2::{Digest, Sha256};

use nv_store::block::MemBlockDevice;
use nv_store::slots;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::{Bank, BankSet, NvBootState};

use machine_mgr::bank_provider::{BankContents, BankProvider};
use sovd_core::{DiagnosticBackend, HeldState, PackageStream};

use component_mgr::backend::{ComponentBackend, ComponentConfig};
use component_mgr::bank_provider::IvdBankProvider;
use component_mgr::bank_spec::BankSetSpec;
use component_mgr::partition_bank_provider::{PartitionBankProvider, PartitionPart};
use component_mgr::suit_provider::SuitProvider;

use sumo_offboard::cose_key::CoseKey;
use sumo_offboard::image_builder::{ComponentSpec as SuitComponentSpec, MultiComponentBuilder};
use sumo_offboard::keygen;

type Nv = Arc<Mutex<NvStore<MemBlockDevice>>>;

/// The parts of the file-bank update: name and payload.
fn parts() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("kernel", vec![0x11; 3000]),
        ("rootfs.img", vec![0x22; 9000]),
        ("vm-config.yaml", b"vm: config\n".to_vec()),
    ]
}

fn fresh_nv() -> Nv {
    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    nv.write_boot_state(&mut NvBootState::default()).unwrap();
    Arc::new(Mutex::new(nv))
}

/// Provision the IVD-signing slot in `tmp/keystore` (idempotent: a restart
/// reuses the same keystore).
fn provisioned_keystore(tmp: &Path) -> PathBuf {
    use hsm::payload::*;
    let ks_dir = tmp.join("keystore");
    if ks_dir.join("provision_state").exists() {
        return ks_dir;
    }
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

type Handles = (
    Arc<Mutex<dyn hsm::HsmProvider>>,
    Arc<dyn hsm::HsmCryptoProvider>,
);

fn hsm_handles(tmp: &Path) -> Handles {
    let ks = provisioned_keystore(tmp);
    (
        Arc::new(Mutex::new(hsm_sim_backend::SimHsm::new(ks.clone()))),
        Arc::new(hsm_sim_backend::SimHsm::new(ks)),
    )
}

fn ivd_provider(
    tmp: &Path,
    nv: &Nv,
    set: BankSet,
    dir: &str,
    (hsm, crypto): Handles,
) -> IvdBankProvider<MemBlockDevice> {
    IvdBankProvider::new(
        nv.clone(),
        set,
        false,
        Some(tmp.join("images")),
        dir.into(),
        Some(hsm),
        None,
        None,
    )
    .with_hsm_crypto(crypto)
}

/// A file-bank `vm1` backend over `tmp/images` — what a machine-manager
/// (re)start builds. Returns the provider handle too, for assertions.
fn file_backend(
    tmp: &Path,
    nv: &Nv,
    key: &CoseKey,
) -> (ComponentBackend<MemBlockDevice>, Arc<dyn BankProvider>) {
    let handles = hsm_handles(tmp);
    let crypto = handles.1.clone();
    let provider: Arc<dyn BankProvider> =
        Arc::new(ivd_provider(tmp, nv, slots::VM1, "vm1", handles));
    let suit = SuitProvider::new(key.public_key_bytes());
    suit.update_keys(key.public_key_bytes(), None, None);
    let backend = ComponentBackend::with_options(
        slots::VM1,
        nv.clone(),
        Arc::new(suit),
        ComponentConfig::default(),
        None,
        Some(tmp.join("images")),
        None,
    )
    .with_id("vm1".into())
    .with_bank_spec(BankSetSpec {
        dir_name: "vm1".into(),
    })
    .with_hsm_crypto(crypto)
    .with_bank_provider(provider.clone());
    (backend, provider)
}

fn stream_of(data: Vec<u8>) -> PackageStream {
    Box::pin(futures::stream::iter(vec![Ok::<
        Bytes,
        Box<dyn std::error::Error + Send + Sync>,
    >(Bytes::from(data))]))
}

fn signed_manifest(key: &CoseKey, component: &str, parts: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut builder = MultiComponentBuilder::new()
        .signing_time(1_700_000_000)
        .sequence_number(1);
    for (name, payload) in parts {
        builder = builder.add_component(SuitComponentSpec {
            id: vec![component.into(), (*name).into()],
            digest: Sha256::digest(payload).to_vec(),
            size: payload.len() as u64,
            uri: format!("#{name}"),
            encryption_info: None,
        });
    }
    builder.build(key).unwrap()
}

fn sha_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Every regular file under `dir`, recursively; empty when `dir` is absent.
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

/// What `x-update-state`'s `banks[]` would report for the inactive bank.
fn inactive(provider: &Arc<dyn BankProvider>) -> Option<BankContents> {
    provider
        .banks()
        .expect("the file provider reports banks")
        .inactive
}

fn image_names(c: &BankContents) -> Vec<&str> {
    c.images.keys().map(String::as_str).collect()
}

async fn upload(backend: &ComponentBackend<MemBlockDevice>, bytes: Vec<u8>) {
    backend
        .receive_package_stream(stream_of(bytes), None)
        .await
        .expect("upload accepted");
}

/// register → manifest → part 1 → restart → register → manifest: part 1 is
/// still there, reported unsealed; part 2 and 3 alone complete the bank, and
/// the seal carries the update id.
#[tokio::test]
async fn a_half_staged_update_survives_a_restart_and_seals_with_its_id() {
    let tmp = tempfile::tempdir().unwrap();
    let nv = fresh_nv();
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let parts = parts();
    let manifest = signed_manifest(&key, "vm1", &parts);
    let bank_b = tmp.path().join("images/vm1/bank_b");

    {
        let (backend, provider) = file_backend(tmp.path(), &nv, &key);
        backend.set_update_id(Some("upd-7".into()));
        backend.start_flash().await.unwrap();
        upload(&backend, manifest.clone()).await;
        upload(&backend, parts[0].1.clone()).await;
        let staged = inactive(&provider).expect("an unsealed bank is reported, not null");
        assert!(!staged.sealed);
        assert_eq!(staged.update_id.as_deref(), Some("upd-7"));
        assert_eq!(image_names(&staged), ["kernel"]);
    } // the machine manager goes away mid-update

    let (backend, provider) = file_backend(tmp.path(), &nv, &key);
    // Before any new session: the facts on disk alone.
    let staged = inactive(&provider).expect("still reported after the restart");
    assert!(!staged.sealed);
    assert_eq!(staged.update_id.as_deref(), Some("upd-7"));
    assert_eq!(
        staged.images["kernel"].sha256.to_vec(),
        Sha256::digest(&parts[0].1).to_vec()
    );

    backend.set_update_id(Some("upd-7".into()));
    backend.start_flash().await.unwrap();
    assert!(bank_b.join("kernel").is_file(), "start_flash wipes nothing");
    upload(&backend, manifest).await;
    let staged = inactive(&provider).unwrap();
    assert!(!staged.sealed);
    assert_eq!(image_names(&staged), ["kernel"], "part 1 kept by digest");

    upload(&backend, parts[1].1.clone()).await;
    upload(&backend, parts[2].1.clone()).await;

    let vm = hsm::ivd::read_manifest_unverified(&bank_b).expect("the bank is sealed");
    assert_eq!(vm.manifest.update_id.as_deref(), Some("upd-7"), "IVD key 7");
    let sealed = inactive(&provider).unwrap();
    assert!(sealed.sealed);
    assert_eq!(sealed.update_id.as_deref(), Some("upd-7"));
    assert_eq!(
        image_names(&sealed),
        ["kernel", "rootfs.img", "vm-config.yaml"]
    );
    let record = provider
        .staging_record(Bank::B)
        .unwrap()
        .expect("the seal keeps the record");
    assert!(record.sealed, "the seal marks the record sealed");
    assert_eq!(record.update_id.as_deref(), Some("upd-7"));
    assert!(!tmp.path().join("images/vm1/staging/bank_b").exists());
}

/// Parts of a file bank are taken by content: out of manifest order works.
#[tokio::test]
async fn file_bank_parts_arrive_in_any_order() {
    let tmp = tempfile::tempdir().unwrap();
    let nv = fresh_nv();
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let parts = parts();
    let (backend, provider) = file_backend(tmp.path(), &nv, &key);

    backend.start_flash().await.unwrap();
    upload(&backend, signed_manifest(&key, "vm1", &parts)).await;
    upload(&backend, parts[2].1.clone()).await;
    // A part sent twice is accepted and changes nothing.
    upload(&backend, parts[2].1.clone()).await;
    assert_eq!(
        image_names(&inactive(&provider).unwrap()),
        ["vm-config.yaml"]
    );
    upload(&backend, parts[0].1.clone()).await;
    upload(&backend, parts[1].1.clone()).await;
    let sealed = inactive(&provider).unwrap();
    assert!(sealed.sealed);
    for (name, payload) in &parts {
        assert_eq!(
            std::fs::read(tmp.path().join("images/vm1/bank_b").join(name)).unwrap(),
            *payload,
            "{name} landed under its own name"
        );
    }
}

/// A payload that is no part of the manifest is refused and leaves nothing
/// in the bank or the staging dir.
#[tokio::test]
async fn a_payload_matching_no_component_is_refused_and_leaves_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let nv = fresh_nv();
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let parts = parts();
    let (backend, provider) = file_backend(tmp.path(), &nv, &key);

    backend.start_flash().await.unwrap();
    upload(&backend, signed_manifest(&key, "vm1", &parts)).await;
    let err = backend
        .receive_package_stream(stream_of(b"no part of this manifest".to_vec()), None)
        .await
        .expect_err("refused");
    assert!(
        format!("{err:?}").contains("matches no component"),
        "got {err:?}"
    );
    assert!(files_under(&tmp.path().join("images/vm1/bank_b")).is_empty());
    assert!(files_under(&tmp.path().join("images/vm1/staging")).is_empty());
    assert!(inactive(&provider).unwrap().images.is_empty());

    // The session still takes the real parts.
    for (_, payload) in &parts {
        upload(&backend, payload.clone()).await;
    }
    assert!(inactive(&provider).unwrap().sealed);
}

/// The next manifest removes a torn staging temp and a stray bank file the
/// record does not name, and drops a recorded part whose bytes changed —
/// which is then staged again.
#[tokio::test]
async fn the_next_manifest_keeps_only_what_still_verifies() {
    let tmp = tempfile::tempdir().unwrap();
    let nv = fresh_nv();
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let parts = parts();
    let manifest = signed_manifest(&key, "vm1", &parts);
    let set = tmp.path().join("images/vm1");
    let bank_b = set.join("bank_b");

    {
        let (backend, _) = file_backend(tmp.path(), &nv, &key);
        backend.start_flash().await.unwrap();
        upload(&backend, manifest.clone()).await;
        upload(&backend, parts[0].1.clone()).await;
        upload(&backend, parts[1].1.clone()).await;
    }
    // Damage between the two runs: a torn upload, a stray file, an altered
    // recorded part.
    std::fs::create_dir_all(set.join("staging/bank_b")).unwrap();
    std::fs::write(set.join("staging/bank_b/upload-torn.part"), b"half").unwrap();
    std::fs::write(bank_b.join("stray.bin"), b"not recorded").unwrap();
    std::fs::write(bank_b.join("rootfs.img"), b"altered").unwrap();

    let (backend, provider) = file_backend(tmp.path(), &nv, &key);
    backend.start_flash().await.unwrap();
    upload(&backend, manifest).await;
    assert!(!set.join("staging/bank_b/upload-torn.part").exists());
    assert!(!bank_b.join("stray.bin").exists());
    assert!(
        !bank_b.join("rootfs.img").exists(),
        "the altered part is gone"
    );
    let staged = inactive(&provider).unwrap();
    assert_eq!(image_names(&staged), ["kernel"]);

    upload(&backend, parts[1].1.clone()).await;
    upload(&backend, parts[2].1.clone()).await;
    assert!(inactive(&provider).unwrap().sealed);
    assert_eq!(
        std::fs::read(bank_b.join("rootfs.img")).unwrap(),
        parts[1].1
    );
}

/// DELETE keeps the parts and forgets the id; the next registration keeps
/// the parts.
#[tokio::test]
async fn abort_keeps_parts_and_clears_the_id() {
    let tmp = tempfile::tempdir().unwrap();
    let nv = fresh_nv();
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let parts = parts();
    let manifest = signed_manifest(&key, "vm1", &parts);
    let (backend, provider) = file_backend(tmp.path(), &nv, &key);

    backend.set_update_id(Some("upd-9".into()));
    let transfer = backend.start_flash().await.unwrap();
    upload(&backend, manifest.clone()).await;
    upload(&backend, parts[1].1.clone()).await;
    backend.abort_flash(&transfer).await.unwrap();

    let staged = inactive(&provider).unwrap();
    assert_eq!(staged.update_id, None, "a part cache, not a held update");
    assert_eq!(image_names(&staged), ["rootfs.img"]);
    assert!(tmp.path().join("images/vm1/bank_b/rootfs.img").is_file());

    backend.start_flash().await.unwrap();
    upload(&backend, manifest).await;
    assert_eq!(image_names(&inactive(&provider).unwrap()), ["rootfs.img"]);
}

/// The sealed inventory is exactly the parts: never the record, never the
/// staging dir.
#[tokio::test]
async fn the_seal_attests_only_the_parts() {
    let tmp = tempfile::tempdir().unwrap();
    let nv = fresh_nv();
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let parts = parts();
    let (backend, _) = file_backend(tmp.path(), &nv, &key);

    backend.start_flash().await.unwrap();
    upload(&backend, signed_manifest(&key, "vm1", &parts)).await;
    for (_, payload) in &parts {
        upload(&backend, payload.clone()).await;
    }
    let vm = hsm::ivd::read_manifest_unverified(&tmp.path().join("images/vm1/bank_b")).unwrap();
    let mut sealed: Vec<(String, String)> = vm
        .manifest
        .files
        .iter()
        .map(|f| (f.relative_path.clone(), hex::encode(&f.sha256)))
        .collect();
    sealed.sort();
    let mut expected: Vec<(String, String)> = parts
        .iter()
        .map(|(n, p)| (n.to_string(), sha_hex(p)))
        .collect();
    expected.sort();
    assert_eq!(sealed, expected);
}

/// A partition bank writes its record beside the metadata dir as parts
/// arrive (in manifest order), leaves the devices to the stream; the seal
/// marks the record sealed and activate removes it.
#[tokio::test]
async fn partition_bank_keeps_a_record_the_seal_marks_it_and_activate_removes_it() {
    let tmp = tempfile::tempdir().unwrap();
    let nv = fresh_nv();
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let parts: Vec<(&str, Vec<u8>)> = vec![("ifs", vec![0xAB; 4096]), ("rootfs", vec![0xCD; 8192])];
    let devices: Vec<(PathBuf, PathBuf)> = parts
        .iter()
        .map(|(name, p)| {
            let a = tmp.path().join(format!("{name}-a.dev"));
            let b = tmp.path().join(format!("{name}-b.dev"));
            std::fs::write(&a, vec![0u8; p.len()]).unwrap();
            std::fs::write(&b, vec![0u8; p.len()]).unwrap();
            (a, b)
        })
        .collect();

    let handles = hsm_handles(tmp.path());
    let (hsm, crypto) = (handles.0.clone(), handles.1.clone());
    let inner = ivd_provider(tmp.path(), &nv, slots::OS, "os", handles);
    let provider: Arc<dyn BankProvider> = Arc::new(PartitionBankProvider::new(
        inner,
        parts
            .iter()
            .zip(&devices)
            .map(|((name, _), (a, b))| PartitionPart {
                file: name.to_string(),
                partition_a: a.to_string_lossy().into_owned(),
                partition_b: b.to_string_lossy().into_owned(),
                record: None,
            })
            .collect(),
        Some(hsm),
        Some(crypto.clone()),
    ));
    let suit = SuitProvider::new(key.public_key_bytes());
    suit.update_keys(key.public_key_bytes(), None, None);
    let backend = ComponentBackend::with_options(
        slots::OS,
        nv.clone(),
        Arc::new(suit),
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
    .with_bank_provider(provider.clone())
    .with_declared_parts(parts.iter().map(|(n, _)| n.to_string()));

    let record = tmp.path().join("images/os/staging-bank_b.cbor");
    backend.start_flash().await.unwrap();
    upload(&backend, signed_manifest(&key, "host", &parts)).await;
    upload(&backend, parts[0].1.clone()).await;

    let staged = provider
        .staging_record(Bank::B)
        .unwrap()
        .expect("record written");
    assert_eq!(staged.parts.len(), 1);
    assert_eq!(staged.parts[0].name, "ifs");
    assert_eq!(staged.parts[0].sha256, sha_hex(&parts[0].1));
    assert!(record.is_file());
    assert_eq!(std::fs::read(&devices[0].1).unwrap(), parts[0].1);
    assert_eq!(
        std::fs::read(&devices[1].1).unwrap(),
        vec![0u8; parts[1].1.len()],
        "the second device waits for its part"
    );

    upload(&backend, parts[1].1.clone()).await;
    assert!(provider.read_installed(Bank::B).is_ok(), "sealed");
    assert!(record.is_file(), "the seal keeps the record");
    assert!(provider.staging_record(Bank::B).unwrap().unwrap().sealed);
    provider.activate(Bank::B).unwrap();
    assert!(!record.exists(), "activate removes the record");
}

/// `prune_target` leaves partition devices alone: they are not files of the
/// metadata dir, so nothing there is kept or removed but the old IVD pair.
#[test]
fn partition_prune_target_leaves_the_devices_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let nv = fresh_nv();
    let dev_a = tmp.path().join("ifs-a.dev");
    let dev_b = tmp.path().join("ifs-b.dev");
    std::fs::write(&dev_a, b"A image").unwrap();
    std::fs::write(&dev_b, b"B image").unwrap();
    let handles = hsm_handles(tmp.path());
    let (hsm, crypto) = (handles.0.clone(), handles.1.clone());
    let inner = ivd_provider(tmp.path(), &nv, slots::OS, "os", handles);
    let provider = PartitionBankProvider::new(
        inner,
        vec![PartitionPart {
            file: "ifs".into(),
            partition_a: dev_a.to_string_lossy().into_owned(),
            partition_b: dev_b.to_string_lossy().into_owned(),
            record: None,
        }],
        Some(hsm),
        Some(crypto),
    );
    provider.prune_target(Bank::B, &["ifs".into()]).unwrap();
    assert_eq!(std::fs::read(&dev_a).unwrap(), b"A image");
    assert_eq!(std::fs::read(&dev_b).unwrap(), b"B image");
}

async fn upload_part(backend: &ComponentBackend<MemBlockDevice>, part_id: &str, bytes: Vec<u8>) {
    backend
        .receive_package_part(part_id, stream_of(bytes), None)
        .await
        .unwrap_or_else(|e| panic!("{part_id}: part refused: {e:?}"));
}

/// Each held update as `(id, bank, state, part names)`.
async fn held(
    backend: &ComponentBackend<MemBlockDevice>,
) -> Vec<(String, String, HeldState, Vec<String>)> {
    backend
        .held_updates()
        .await
        .unwrap()
        .into_iter()
        .map(|h| {
            (
                h.id,
                h.bank,
                h.state,
                h.parts.into_iter().map(|p| p.name).collect(),
            )
        })
        .collect()
}

fn names(parts: &[(&str, Vec<u8>)]) -> Vec<String> {
    let mut n: Vec<String> = parts.iter().map(|(n, _)| n.to_string()).collect();
    n.sort();
    n
}

/// A part named by uri, by name or by `#name` lands as that part, in any
/// order, and the bank seals.
#[tokio::test]
async fn file_bank_takes_addressed_parts_in_any_order() {
    let tmp = tempfile::tempdir().unwrap();
    let nv = fresh_nv();
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let parts = parts();
    let (backend, provider) = file_backend(tmp.path(), &nv, &key);

    backend.start_flash().await.unwrap();
    upload_part(&backend, "manifest", signed_manifest(&key, "vm1", &parts)).await;
    upload_part(&backend, "vm-config.yaml", parts[2].1.clone()).await;
    upload_part(&backend, "#rootfs.img", parts[1].1.clone()).await;
    // Present already: accepted, nothing written.
    upload_part(&backend, "#rootfs.img", parts[1].1.clone()).await;
    upload_part(&backend, "#kernel", parts[0].1.clone()).await;
    assert!(inactive(&provider).unwrap().sealed);
    for (name, payload) in &parts {
        assert_eq!(
            std::fs::read(tmp.path().join("images/vm1/bank_b").join(name)).unwrap(),
            *payload
        );
    }
}

/// An addressed part whose bytes are not that part's digest is refused in
/// the stream and nothing lands.
#[tokio::test]
async fn an_addressed_part_with_the_wrong_digest_is_refused_and_leaves_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let nv = fresh_nv();
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let parts = parts();
    let (backend, provider) = file_backend(tmp.path(), &nv, &key);

    backend.start_flash().await.unwrap();
    upload_part(&backend, "manifest", signed_manifest(&key, "vm1", &parts)).await;
    // Another part's bytes under this name: a real part, the wrong digest.
    backend
        .receive_package_part("#kernel", stream_of(parts[1].1.clone()), None)
        .await
        .expect_err("refused");
    assert!(files_under(&tmp.path().join("images/vm1/bank_b")).is_empty());
    assert!(files_under(&tmp.path().join("images/vm1/staging")).is_empty());
    assert!(inactive(&provider).unwrap().images.is_empty());
    let record = provider.staging_record(Bank::B).unwrap().unwrap();
    assert!(record.parts.is_empty());

    upload_part(&backend, "#kernel", parts[0].1.clone()).await;
    assert_eq!(image_names(&inactive(&provider).unwrap()), ["kernel"]);
}

/// A part id that names no part keeps the unnamed intake: by content on a
/// file bank.
#[tokio::test]
async fn an_unresolvable_part_id_is_taken_by_content() {
    let tmp = tempfile::tempdir().unwrap();
    let nv = fresh_nv();
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let parts = parts();
    let (backend, provider) = file_backend(tmp.path(), &nv, &key);

    backend.start_flash().await.unwrap();
    upload_part(&backend, "manifest", signed_manifest(&key, "vm1", &parts)).await;
    upload_part(&backend, "payload-2", parts[1].1.clone()).await;
    assert_eq!(image_names(&inactive(&provider).unwrap()), ["rootfs.img"]);
}

/// The client's registration id, noted before `start_flash` (the order SOVDd
/// calls them in), ends up in the record and in IVD key 7; noted again while
/// the session is open, it renames the record.
#[tokio::test]
async fn note_update_id_before_start_flash_reaches_the_record_and_the_seal() {
    let tmp = tempfile::tempdir().unwrap();
    let nv = fresh_nv();
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let parts = parts();
    let (backend, provider) = file_backend(tmp.path(), &nv, &key);

    backend.note_update_id("upd-1").await.unwrap();
    backend.start_flash().await.unwrap();
    upload(&backend, signed_manifest(&key, "vm1", &parts)).await;
    let record = provider.staging_record(Bank::B).unwrap().unwrap();
    assert_eq!(record.update_id.as_deref(), Some("upd-1"));

    upload(&backend, parts[0].1.clone()).await;
    backend.note_update_id("upd-2").await.unwrap();
    let record = provider.staging_record(Bank::B).unwrap().unwrap();
    assert_eq!(
        record.update_id.as_deref(),
        Some("upd-2"),
        "renamed in session"
    );

    upload(&backend, parts[1].1.clone()).await;
    upload(&backend, parts[2].1.clone()).await;
    let vm = hsm::ivd::read_manifest_unverified(&tmp.path().join("images/vm1/bank_b")).unwrap();
    assert_eq!(vm.manifest.update_id.as_deref(), Some("upd-2"), "IVD key 7");
}

/// Preparing while parts arrive, Prepared once sealed — across a restart —
/// and Executed in trial; a commit leaves nothing held.
#[tokio::test]
async fn held_updates_follow_the_facts_through_to_commit() {
    let tmp = tempfile::tempdir().unwrap();
    let nv = fresh_nv();
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let parts = parts();
    let manifest = signed_manifest(&key, "vm1", &parts);

    {
        let (backend, _) = file_backend(tmp.path(), &nv, &key);
        assert!(held(&backend).await.is_empty(), "nothing before an update");
        backend.note_update_id("upd-3").await.unwrap();
        backend.start_flash().await.unwrap();
        upload(&backend, manifest.clone()).await;
        upload(&backend, parts[0].1.clone()).await;
        assert_eq!(
            held(&backend).await,
            [(
                "upd-3".into(),
                "B".into(),
                HeldState::Preparing,
                vec!["kernel".into()]
            )]
        );
        upload(&backend, parts[1].1.clone()).await;
        upload(&backend, parts[2].1.clone()).await;
        assert_eq!(
            held(&backend).await,
            [(
                "upd-3".into(),
                "B".into(),
                HeldState::Prepared,
                names(&parts)
            )]
        );
    } // restart between seal and activate

    let (backend, provider) = file_backend(tmp.path(), &nv, &key);
    assert_eq!(
        held(&backend).await,
        [(
            "upd-3".into(),
            "B".into(),
            HeldState::Prepared,
            names(&parts)
        )],
        "Prepared is a fact on disk"
    );

    // The client resumes: every part is kept, the bank seals at the manifest,
    // and executing arms it — the record goes, the trial carries the update.
    backend.note_update_id("upd-3").await.unwrap();
    backend.start_flash().await.unwrap();
    upload(&backend, manifest).await;
    backend.finalize_flash().await.unwrap();
    assert!(provider.staging_record(Bank::B).unwrap().is_none());
    drop(backend);

    // The node comes back up on the armed bank (no boot vector here: the
    // provider reads it from NV at start).
    let (backend, _) = file_backend(tmp.path(), &nv, &key);
    assert_eq!(
        held(&backend).await,
        [(
            "upd-3".into(),
            "B".into(),
            HeldState::Executed,
            names(&parts)
        )]
    );

    backend.commit_flash().await.unwrap();
    assert!(
        held(&backend).await.is_empty(),
        "a committed bank is not held"
    );
}

/// A rolled-back update is not held: the record went at activate and the
/// trial is over.
#[tokio::test]
async fn a_rolled_back_update_is_not_held() {
    let tmp = tempfile::tempdir().unwrap();
    let nv = fresh_nv();
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let parts = parts();
    {
        let (backend, _) = file_backend(tmp.path(), &nv, &key);
        backend.note_update_id("upd-4").await.unwrap();
        backend.start_flash().await.unwrap();
        upload(&backend, signed_manifest(&key, "vm1", &parts)).await;
        for (_, payload) in &parts {
            upload(&backend, payload.clone()).await;
        }
        backend.finalize_flash().await.unwrap();
    }
    let (backend, provider) = file_backend(tmp.path(), &nv, &key);
    assert_eq!(held(&backend).await[0].2, HeldState::Executed);
    backend.rollback_flash().await.unwrap();
    assert!(
        held(&backend).await.is_empty(),
        "a rolled-back bank is not held"
    );
    drop((backend, provider));

    // Back on the committed bank after the reboot: still nothing.
    let (backend, provider) = file_backend(tmp.path(), &nv, &key);
    assert_eq!(provider.banks().unwrap().active.bank, Bank::A);
    assert!(provider.staging_record(Bank::B).unwrap().is_none());
    assert!(
        held(&backend).await.is_empty(),
        "a rolled-back bank is not held"
    );
}

/// A record an abort stripped of its id is a part cache, not held.
#[tokio::test]
async fn a_record_without_an_id_is_not_held() {
    let tmp = tempfile::tempdir().unwrap();
    let nv = fresh_nv();
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let parts = parts();
    let (backend, provider) = file_backend(tmp.path(), &nv, &key);

    backend.note_update_id("upd-5").await.unwrap();
    let transfer = backend.start_flash().await.unwrap();
    upload(&backend, signed_manifest(&key, "vm1", &parts)).await;
    upload(&backend, parts[0].1.clone()).await;
    assert_eq!(held(&backend).await.len(), 1);
    backend.abort_flash(&transfer).await.unwrap();
    assert!(provider.staging_record(Bank::B).unwrap().is_some());
    assert!(held(&backend).await.is_empty());
}

/// Stage every part under `id`, execute, and come back up on the armed bank
/// to commit it.
async fn install_and_commit(tmp: &Path, nv: &Nv, key: &CoseKey, id: &str) {
    let parts = parts();
    {
        let (backend, _) = file_backend(tmp, nv, key);
        backend.note_update_id(id).await.unwrap();
        backend.start_flash().await.unwrap();
        upload(&backend, signed_manifest(key, "vm1", &parts)).await;
        for (_, payload) in &parts {
            upload(&backend, payload.clone()).await;
        }
        backend.finalize_flash().await.unwrap();
    }
    let (backend, _) = file_backend(tmp, nv, key);
    backend.commit_flash().await.unwrap();
}

/// After a second committed update, the previous bank still carries the
/// first update's seal and id, and is not held.
#[tokio::test]
async fn a_committed_previous_bank_is_not_held() {
    let tmp = tempfile::tempdir().unwrap();
    let nv = fresh_nv();
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    install_and_commit(tmp.path(), &nv, &key, "upd-6").await;
    install_and_commit(tmp.path(), &nv, &key, "upd-7").await;

    let (backend, provider) = file_backend(tmp.path(), &nv, &key);
    let banks = provider.banks().unwrap();
    assert_eq!(banks.active.update_id.as_deref(), Some("upd-7"));
    let previous = banks.inactive.expect("the previous bank is reported");
    assert!(previous.sealed);
    assert_eq!(previous.update_id.as_deref(), Some("upd-6"));
    assert!(held(&backend).await.is_empty());
}
