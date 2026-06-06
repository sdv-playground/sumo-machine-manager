//! Integration tests for the multi-component streaming pipeline.
//!
//! Tests cover:
//! - Single-component unencrypted payload (baseline)
//! - Single-component encrypted payload (ECDH-ES+A128KW)
//! - Multi-component (kernel + rootfs) in one envelope
//! - Chunked delivery (envelope split across multiple stream chunks)
//! - Corrupted payload (wrong bytes mid-stream, digest mismatch)
//! - Truncated transfer (stream ends early)
//! - Wrong encryption key (device key mismatch)

use std::io::{BufWriter, Write};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures::stream;
use nv_store::block::MemBlockDevice;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::{Bank, BankSet, NvBootState};
use sumo_crypto::{CryptoBackend, RustCryptoBackend};
use sumo_offboard::cose_key::CoseKey;
use sumo_offboard::encryptor;
use sumo_offboard::image_builder::{ComponentSpec, ImageManifestBuilder, MultiComponentBuilder};
use sumo_offboard::keygen;
use sumo_offboard::recipient::Recipient;

use vm_mgr::bank_provider::IvdBankProvider;
use vm_mgr::bank_spec::BankSetSpec;
use vm_mgr::streaming::process_envelope_stream;
use vm_mgr::suit_provider::SuitProvider;

type PackageStream = Pin<
    Box<dyn futures::Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync>>> + Send>,
>;

/// Build an `IvdBankProvider` rooted at `images_dir` for `set` so
/// `process_envelope_stream` writes payloads to `images_dir/<set>/bank_x/`.
/// NV is a throwaway MemBlockDevice — `open_payload_writer` only consults
/// the images_dir + dir_name, not NV.
fn provider_for(images_dir: &Path, set: BankSet) -> IvdBankProvider<MemBlockDevice> {
    let dev = MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize);
    let mut nv = NvStore::new(dev);
    let mut state = NvBootState::default();
    nv.write_boot_state(&mut state).unwrap();
    let dir_name = BankSetSpec::for_well_known(set).dir_name;
    IvdBankProvider::new(
        Arc::new(Mutex::new(nv)),
        set,
        false,
        Some(images_dir.to_path_buf()),
        dir_name,
        None,
        None,
        None,
    )
}

/// A `Box<dyn Write + Send>` sink at `path` (parent dirs created) — the
/// writer shape `process_raw_payload` now takes instead of a path.
fn file_writer(path: &Path) -> Box<dyn Write + Send> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    Box::new(BufWriter::new(std::fs::File::create(path).unwrap()))
}

/// Helper: generate test keys.
fn test_keys() -> (CoseKey, CoseKey) {
    let signing = keygen::generate_signing_key(keygen::ES256).unwrap();
    let device = keygen::generate_device_key(keygen::ES256).unwrap();
    (signing, device)
}

/// Helper: create a SuitProvider with test keys. The optional device
/// key is wrapped in an [`InMemoryKeyUnwrap`] so the decryptor can
/// route CEK unwrap through the same trait shape used in production
/// (production wires an HSM-backed `HsmKeyUnwrap` instead).
fn test_provider(signing_key: &CoseKey, device_key: Option<&CoseKey>) -> SuitProvider {
    let pub_bytes = signing_key.public_key_bytes();
    let provider = SuitProvider::new(pub_bytes);
    // Owned CoseKey + a static-RustCrypto-backend boxed into an Arc'd
    // `KeyUnwrap` so it satisfies the trait object's `'static` bound.
    let unwrap: Option<std::sync::Arc<dyn sumo_onboard::decryptor::KeyUnwrap + Send + Sync>> =
        device_key.map(|dk| {
            std::sync::Arc::new(OwnedInMemoryUnwrap {
                device_key_cbor: dk.to_cose_key_bytes(),
            }) as std::sync::Arc<dyn sumo_onboard::decryptor::KeyUnwrap + Send + Sync>
        });
    provider.update_keys(signing_key.public_key_bytes(), unwrap, None);
    provider
}

/// Test-only adapter that owns the serialized CoseKey so the trait
/// object meets `'static` (InMemoryKeyUnwrap takes references). Each
/// call deserializes — fine for tests, not for production hot paths.
struct OwnedInMemoryUnwrap {
    device_key_cbor: Vec<u8>,
}

impl OwnedInMemoryUnwrap {
    fn parsed(&self) -> coset::CoseKey {
        <coset::CoseKey as coset::CborSerializable>::from_slice(&self.device_key_cbor)
            .expect("test device key cbor")
    }
}

impl sumo_onboard::decryptor::KeyUnwrap for OwnedInMemoryUnwrap {
    fn unwrap_cek_a128kw(
        &self,
        wrapped_cek: &[u8],
    ) -> Result<Vec<u8>, sumo_onboard::error::Sum2Error> {
        let key = self.parsed();
        let crypto = sumo_crypto::RustCryptoBackend::new();
        sumo_onboard::decryptor::InMemoryKeyUnwrap::new(&key, &crypto)
            .unwrap_cek_a128kw(wrapped_cek)
    }
    fn unwrap_cek_ecdh_es(
        &self,
        ephem_pub: &[u8],
        wrapped_cek: &[u8],
        recipient_protected: &[u8],
    ) -> Result<Vec<u8>, sumo_onboard::error::Sum2Error> {
        let key = self.parsed();
        let crypto = sumo_crypto::RustCryptoBackend::new();
        sumo_onboard::decryptor::InMemoryKeyUnwrap::new(&key, &crypto).unwrap_cek_ecdh_es(
            ephem_pub,
            wrapped_cek,
            recipient_protected,
        )
    }
}

/// Helper: create a PackageStream from bytes.
fn stream_from_bytes(data: Vec<u8>) -> PackageStream {
    Box::pin(stream::iter(vec![Ok(Bytes::from(data))]))
}

/// Helper: create a chunked PackageStream.
fn stream_chunked(data: Vec<u8>, chunk_size: usize) -> PackageStream {
    let chunks: Vec<_> = data
        .chunks(chunk_size)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    Box::pin(stream::iter(chunks))
}

/// Helper: encrypt a payload with ECDH-ES+A128KW.
fn encrypt_payload(plaintext: &[u8], device_key: &CoseKey) -> encryptor::EncryptedPayload {
    let sender = keygen::generate_device_key(keygen::ES256).unwrap();
    let pub_key = CoseKey::from_cose_key_bytes(&device_key.public_key_bytes()).unwrap();
    encryptor::encrypt_firmware_ecdh(
        plaintext,
        &sender,
        &[Recipient {
            public_key: pub_key,
            kid: b"test".to_vec(),
        }],
    )
    .unwrap()
}

// =============================================================================
// Successful cases
// =============================================================================

#[tokio::test]
async fn single_component_unencrypted() {
    let (signing_key, _) = test_keys();
    let provider = test_provider(&signing_key, None);
    let crypto = RustCryptoBackend::new();

    let payload = vec![0x42u8; 4096];
    let digest = crypto.sha256(&payload);

    let envelope = ImageManifestBuilder::new()
        .component_id(vec!["vm1".to_string()])
        .sequence_number(1)
        .security_version(1)
        .payload_digest(&digest, payload.len() as u64)
        .payload_uri("#firmware".to_string())
        .integrated_payload("#firmware".to_string(), payload.clone())
        .text_version("1.0.0")
        .build(&signing_key)
        .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let bank_provider = provider_for(tmp.path(), BankSet::Vm1);
    let result = process_envelope_stream(
        stream_from_bytes(envelope),
        &provider,
        0,
        Some(&bank_provider),
        BankSet::Vm1,
        &vm_mgr::bank_spec::BankSetSpec::for_well_known(BankSet::Vm1),
        Bank::A,
    )
    .await;

    let v = result.unwrap();
    assert_eq!(v.image_size, Some(4096));
    assert_eq!(v.image_sha256, Some(digest));

    // Verify file on disk
    let written = std::fs::read(tmp.path().join("vm1/bank_a/rootfs.img")).unwrap();
    assert_eq!(written, payload);
}

#[tokio::test]
async fn single_component_encrypted() {
    let (signing_key, device_key) = test_keys();
    let provider = test_provider(&signing_key, Some(&device_key));
    let crypto = RustCryptoBackend::new();

    let plaintext = vec![0xAB; 8192];
    let digest = crypto.sha256(&plaintext);
    let encrypted = encrypt_payload(&plaintext, &device_key);

    let envelope = ImageManifestBuilder::new()
        .component_id(vec!["vm1".to_string()])
        .sequence_number(1)
        .security_version(1)
        .payload_digest(&digest, plaintext.len() as u64)
        .payload_uri("#firmware".to_string())
        .encryption_info(&encrypted.encryption_info)
        .integrated_payload("#firmware".to_string(), encrypted.ciphertext)
        .text_version("1.0.0")
        .build(&signing_key)
        .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let bank_provider = provider_for(tmp.path(), BankSet::Vm1);
    let result = process_envelope_stream(
        stream_from_bytes(envelope),
        &provider,
        0,
        Some(&bank_provider),
        BankSet::Vm1,
        &vm_mgr::bank_spec::BankSetSpec::for_well_known(BankSet::Vm1),
        Bank::A,
    )
    .await;

    let v = result.unwrap();
    assert_eq!(v.image_size, Some(8192));

    // Decrypted file should match original plaintext
    let written = std::fs::read(tmp.path().join("vm1/bank_a/rootfs.img")).unwrap();
    assert_eq!(written, plaintext);
}

/// Multi-component: separate manifest + raw payload uploads (the new way).
///
/// Upload manifest (validate), save payloads as raw files, then process
/// each payload using the manifest's component info.
#[test]
fn multi_component_separate_uploads() {
    use vm_mgr::streaming::{process_raw_payload, validate_manifest};

    let (signing_key, _) = test_keys();
    let provider = test_provider(&signing_key, None);
    let crypto = RustCryptoBackend::new();

    let kernel = vec![0xBB; 2048];
    let rootfs = vec![0xCC; 16384];
    let kernel_digest = crypto.sha256(&kernel);
    let rootfs_digest = crypto.sha256(&rootfs);

    // Build manifest (no integrated payloads — just metadata)
    let manifest = MultiComponentBuilder::new()
        .sequence_number(1)
        .security_version(1)
        .text_version("1.0.0")
        .add_component(ComponentSpec {
            id: vec!["vm1".into(), "kernel".into()],
            digest: kernel_digest.to_vec(),
            size: kernel.len() as u64,
            uri: "#kernel".into(),
            encryption_info: None,
        })
        .add_component(ComponentSpec {
            id: vec!["vm1".into(), "rootfs".into()],
            digest: rootfs_digest.to_vec(),
            size: rootfs.len() as u64,
            uri: "#firmware".into(),
            encryption_info: None,
        })
        .build(&signing_key)
        .unwrap();

    let tmp = tempfile::tempdir().unwrap();

    // Step 1: Validate manifest (tiny, ~1KB)
    let validated = validate_manifest(&manifest, &provider, 0).unwrap();
    assert_eq!(validated.bank_set, BankSet::Vm1);

    // Step 2: Save payloads as raw files (simulating separate uploads)
    let kernel_path = tmp.path().join("upload-kernel.bin");
    let rootfs_path = tmp.path().join("upload-rootfs.bin");
    std::fs::write(&kernel_path, &kernel).unwrap();
    std::fs::write(&rootfs_path, &rootfs).unwrap();

    // Step 3: Process each payload using manifest encryption info
    let kernel_out = tmp.path().join("vm1-kernel-staged.img");
    let (ksize, khash) = process_raw_payload(
        &kernel_path,
        &manifest,
        0,
        None,
        &kernel_digest,
        file_writer(&kernel_out),
    )
    .unwrap();
    assert_eq!(ksize, 2048);
    assert_eq!(khash, kernel_digest);

    let rootfs_out = tmp.path().join("vm1-staged.img");
    let (rsize, rhash) = process_raw_payload(
        &rootfs_path,
        &manifest,
        1,
        None,
        &rootfs_digest,
        file_writer(&rootfs_out),
    )
    .unwrap();
    assert_eq!(rsize, 16384);
    assert_eq!(rhash, rootfs_digest);

    // Verify files on disk match originals
    assert_eq!(std::fs::read(&kernel_out).unwrap(), kernel);
    assert_eq!(std::fs::read(&rootfs_out).unwrap(), rootfs);
}

/// Multi-component with encryption: separate manifest + encrypted raw payloads.
#[test]
fn multi_component_encrypted_separate() {
    use vm_mgr::streaming::process_raw_payload;

    let (signing_key, device_key) = test_keys();
    let crypto = RustCryptoBackend::new();

    let kernel = vec![0xBB; 2048];
    let rootfs = vec![0xCC; 8192];
    let kernel_digest = crypto.sha256(&kernel);
    let rootfs_digest = crypto.sha256(&rootfs);

    let kernel_enc = encrypt_payload(&kernel, &device_key);
    let rootfs_enc = encrypt_payload(&rootfs, &device_key);

    let manifest = MultiComponentBuilder::new()
        .sequence_number(1)
        .security_version(1)
        .add_component(ComponentSpec {
            id: vec!["vm1".into(), "kernel".into()],
            digest: kernel_digest.to_vec(),
            size: kernel.len() as u64,
            uri: "#kernel".into(),
            encryption_info: Some(kernel_enc.encryption_info.clone()),
        })
        .add_component(ComponentSpec {
            id: vec!["vm1".into(), "rootfs".into()],
            digest: rootfs_digest.to_vec(),
            size: rootfs.len() as u64,
            uri: "#firmware".into(),
            encryption_info: Some(rootfs_enc.encryption_info.clone()),
        })
        .build(&signing_key)
        .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    // Wrap the device key in a KeyUnwrap impl so process_raw_payload
    // gets the same shape as production. Test-only — production wires
    // an HSM-backed HsmKeyUnwrap instead, which keeps the EC scalar
    // inside the secure element.
    let dk_unwrap = OwnedInMemoryUnwrap {
        device_key_cbor: device_key.to_cose_key_bytes(),
    };

    // Save encrypted payloads as raw files
    let kernel_path = tmp.path().join("upload-kernel.bin");
    let rootfs_path = tmp.path().join("upload-rootfs.bin");
    std::fs::write(&kernel_path, &kernel_enc.ciphertext).unwrap();
    std::fs::write(&rootfs_path, &rootfs_enc.ciphertext).unwrap();

    // Process each — decrypt + verify
    let kernel_out = tmp.path().join("vm1-kernel-staged.img");
    let (ksize, _) = process_raw_payload(
        &kernel_path,
        &manifest,
        0,
        Some(&dk_unwrap as &(dyn sumo_onboard::decryptor::KeyUnwrap + Send + Sync)),
        &kernel_digest,
        file_writer(&kernel_out),
    )
    .unwrap();
    assert_eq!(ksize, 2048);
    assert_eq!(std::fs::read(&kernel_out).unwrap(), kernel);

    let rootfs_out = tmp.path().join("vm1-staged.img");
    let (rsize, _) = process_raw_payload(
        &rootfs_path,
        &manifest,
        1,
        Some(&dk_unwrap as &(dyn sumo_onboard::decryptor::KeyUnwrap + Send + Sync)),
        &rootfs_digest,
        file_writer(&rootfs_out),
    )
    .unwrap();
    assert_eq!(rsize, 8192);
    assert_eq!(std::fs::read(&rootfs_out).unwrap(), rootfs);
}

/// Corrupt payload fails digest verification.
#[test]
fn raw_payload_corrupt_fails() {
    use vm_mgr::streaming::process_raw_payload;

    let (signing_key, _) = test_keys();
    let crypto = RustCryptoBackend::new();

    let payload = vec![0x42u8; 4096];
    let digest = crypto.sha256(&payload);

    let manifest = ImageManifestBuilder::new()
        .component_id(vec!["vm1".into()])
        .sequence_number(1)
        .payload_digest(&digest, payload.len() as u64)
        .payload_uri("#firmware".into())
        .build(&signing_key)
        .unwrap();

    let tmp = tempfile::tempdir().unwrap();

    // Write corrupted payload
    let mut corrupted = payload.clone();
    corrupted[100] ^= 0xFF;
    let payload_path = tmp.path().join("corrupt.bin");
    std::fs::write(&payload_path, &corrupted).unwrap();

    let out = tmp.path().join("staged.img");
    let result = process_raw_payload(
        &payload_path,
        &manifest,
        0,
        None,
        &digest,
        file_writer(&out),
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn chunked_delivery() {
    let (signing_key, _) = test_keys();
    let provider = test_provider(&signing_key, None);
    let crypto = RustCryptoBackend::new();

    let payload = vec![0x55u8; 32768];
    let digest = crypto.sha256(&payload);

    let envelope = ImageManifestBuilder::new()
        .component_id(vec!["vm1".to_string()])
        .sequence_number(1)
        .security_version(1)
        .payload_digest(&digest, payload.len() as u64)
        .payload_uri("#firmware".to_string())
        .integrated_payload("#firmware".to_string(), payload.clone())
        .build(&signing_key)
        .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    // Split into 512-byte chunks
    let bank_provider = provider_for(tmp.path(), BankSet::Vm1);
    let result = process_envelope_stream(
        stream_chunked(envelope, 512),
        &provider,
        0,
        Some(&bank_provider),
        BankSet::Vm1,
        &vm_mgr::bank_spec::BankSetSpec::for_well_known(BankSet::Vm1),
        Bank::A,
    )
    .await;

    let v = result.unwrap();
    assert_eq!(v.image_size, Some(32768));

    let written = std::fs::read(tmp.path().join("vm1/bank_a/rootfs.img")).unwrap();
    assert_eq!(written, payload);
}

// =============================================================================
// Error cases
// =============================================================================

#[tokio::test]
async fn corrupted_payload_digest_mismatch() {
    let (signing_key, _) = test_keys();
    let provider = test_provider(&signing_key, None);
    let crypto = RustCryptoBackend::new();

    let payload = vec![0x42u8; 4096];
    let digest = crypto.sha256(&payload);

    // Corrupt the payload (flip a byte)
    let mut corrupted = payload.clone();
    corrupted[100] ^= 0xFF;

    let envelope = ImageManifestBuilder::new()
        .component_id(vec!["vm1".to_string()])
        .sequence_number(1)
        .security_version(1)
        .payload_digest(&digest, payload.len() as u64) // digest of ORIGINAL
        .payload_uri("#firmware".to_string())
        .integrated_payload("#firmware".to_string(), corrupted) // CORRUPTED data
        .build(&signing_key)
        .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let bank_provider = provider_for(tmp.path(), BankSet::Vm1);
    let result = process_envelope_stream(
        stream_from_bytes(envelope),
        &provider,
        0,
        Some(&bank_provider),
        BankSet::Vm1,
        &vm_mgr::bank_spec::BankSetSpec::for_well_known(BankSet::Vm1),
        Bank::A,
    )
    .await;

    assert!(result.is_err());
    let err = result.err().expect("expected error").to_string();
    assert!(
        err.contains("digest") || err.contains("hash") || err.contains("mismatch"),
        "expected digest error, got: {err}"
    );
}

#[tokio::test]
async fn truncated_transfer() {
    let (signing_key, _) = test_keys();
    let provider = test_provider(&signing_key, None);
    let crypto = RustCryptoBackend::new();

    let payload = vec![0x42u8; 4096];
    let digest = crypto.sha256(&payload);

    let envelope = ImageManifestBuilder::new()
        .component_id(vec!["vm1".to_string()])
        .sequence_number(1)
        .security_version(1)
        .payload_digest(&digest, payload.len() as u64)
        .payload_uri("#firmware".to_string())
        .integrated_payload("#firmware".to_string(), payload.clone())
        .build(&signing_key)
        .unwrap();

    // Truncate the envelope at 80% — cuts off part of the payload
    let truncated = envelope[..envelope.len() * 80 / 100].to_vec();

    let tmp = tempfile::tempdir().unwrap();
    let bank_provider = provider_for(tmp.path(), BankSet::Vm1);
    let result = process_envelope_stream(
        stream_from_bytes(truncated),
        &provider,
        0,
        Some(&bank_provider),
        BankSet::Vm1,
        &vm_mgr::bank_spec::BankSetSpec::for_well_known(BankSet::Vm1),
        Bank::A,
    )
    .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn wrong_device_key() {
    let (signing_key, device_key) = test_keys();
    let crypto = RustCryptoBackend::new();

    let plaintext = vec![0xAB; 4096];
    let digest = crypto.sha256(&plaintext);
    let encrypted = encrypt_payload(&plaintext, &device_key);

    let envelope = ImageManifestBuilder::new()
        .component_id(vec!["vm1".to_string()])
        .sequence_number(1)
        .security_version(1)
        .payload_digest(&digest, plaintext.len() as u64)
        .payload_uri("#firmware".to_string())
        .encryption_info(&encrypted.encryption_info)
        .integrated_payload("#firmware".to_string(), encrypted.ciphertext)
        .build(&signing_key)
        .unwrap();

    // Use a DIFFERENT device key — decryption should fail
    let wrong_key = keygen::generate_device_key(keygen::ES256).unwrap();
    let provider = test_provider(&signing_key, Some(&wrong_key));

    let tmp = tempfile::tempdir().unwrap();
    let bank_provider = provider_for(tmp.path(), BankSet::Vm1);
    let result = process_envelope_stream(
        stream_from_bytes(envelope),
        &provider,
        0,
        Some(&bank_provider),
        BankSet::Vm1,
        &vm_mgr::bank_spec::BankSetSpec::for_well_known(BankSet::Vm1),
        Bank::A,
    )
    .await;

    assert!(result.is_err());
    let err = result.err().expect("expected error").to_string();
    assert!(
        err.contains("decrypt") || err.contains("Decrypt") || err.contains("crypto"),
        "expected decrypt error, got: {err}"
    );
}

#[tokio::test]
async fn anti_rollback_rejects_old_security_version() {
    let (signing_key, _) = test_keys();
    let provider = test_provider(&signing_key, None);
    let crypto = RustCryptoBackend::new();

    let payload = vec![0x42u8; 1024];
    let digest = crypto.sha256(&payload);

    let envelope = ImageManifestBuilder::new()
        .component_id(vec!["vm1".to_string()])
        .sequence_number(1)
        .security_version(1) // manifest says secver=1
        .payload_digest(&digest, payload.len() as u64)
        .payload_uri("#firmware".to_string())
        .integrated_payload("#firmware".to_string(), payload)
        .build(&signing_key)
        .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let bank_provider = provider_for(tmp.path(), BankSet::Vm1);
    let result = process_envelope_stream(
        stream_from_bytes(envelope),
        &provider,
        5, // min_security_ver = 5 — higher than manifest's 1
        Some(&bank_provider),
        BankSet::Vm1,
        &vm_mgr::bank_spec::BankSetSpec::for_well_known(BankSet::Vm1),
        Bank::A,
    )
    .await;

    assert!(result.is_err());
    let err = result.err().expect("expected error").to_string();
    assert!(
        err.contains("security") || err.contains("rollback") || err.contains("version"),
        "expected anti-rollback error, got: {err}"
    );
}

#[tokio::test]
async fn stream_error_mid_transfer() {
    let (signing_key, _) = test_keys();
    let provider = test_provider(&signing_key, None);
    let crypto = RustCryptoBackend::new();

    let payload = vec![0x42u8; 4096];
    let digest = crypto.sha256(&payload);

    let envelope = ImageManifestBuilder::new()
        .component_id(vec!["vm1".to_string()])
        .sequence_number(1)
        .security_version(1)
        .payload_digest(&digest, payload.len() as u64)
        .payload_uri("#firmware".to_string())
        .integrated_payload("#firmware".to_string(), payload)
        .build(&signing_key)
        .unwrap();

    // Deliver first half, then an error
    let half = envelope.len() / 2;
    let chunks: Vec<Result<Bytes, Box<dyn std::error::Error + Send + Sync>>> = vec![
        Ok(Bytes::copy_from_slice(&envelope[..half])),
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "connection lost",
        ))),
    ];
    let stream: PackageStream = Box::pin(stream::iter(chunks));

    let tmp = tempfile::tempdir().unwrap();
    let bank_provider = provider_for(tmp.path(), BankSet::Vm1);
    let result = process_envelope_stream(
        stream,
        &provider,
        0,
        Some(&bank_provider),
        BankSet::Vm1,
        &vm_mgr::bank_spec::BankSetSpec::for_well_known(BankSet::Vm1),
        Bank::A,
    )
    .await;

    assert!(result.is_err());
}
