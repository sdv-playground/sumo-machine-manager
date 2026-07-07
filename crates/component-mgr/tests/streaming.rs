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
use sumo_offboard::campaign_builder::CampaignBuilder;
use sumo_offboard::cose_key::CoseKey;
use sumo_offboard::encryptor;
use sumo_offboard::image_builder::{ComponentSpec, ImageManifestBuilder, MultiComponentBuilder};
use sumo_offboard::keygen;
use sumo_offboard::recipient::Recipient;

use component_mgr::bank_provider::IvdBankProvider;
use component_mgr::bank_spec::BankSetSpec;
use component_mgr::streaming::process_envelope_stream;
use component_mgr::suit_provider::SuitProvider;
use puller::Puller;

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
        .signing_time(1_700_000_000)
        .component_id(vec!["vm1".to_string(), "rootfs.img".to_string()])
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
        .signing_time(1_700_000_000)
        .component_id(vec!["vm1".to_string(), "rootfs.img".to_string()])
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
    use component_mgr::streaming::{process_raw_payload, validate_manifest};

    let (signing_key, _) = test_keys();
    let provider = test_provider(&signing_key, None);
    let crypto = RustCryptoBackend::new();

    let kernel = vec![0xBB; 2048];
    let rootfs = vec![0xCC; 16384];
    let kernel_digest = crypto.sha256(&kernel);
    let rootfs_digest = crypto.sha256(&rootfs);

    // Build manifest (no integrated payloads — just metadata)
    let manifest = MultiComponentBuilder::new()
        .signing_time(1_700_000_000)
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
    // The signed manifest signing time (iat) flows offboard → validate →
    // ValidatedFirmware, so the install path can ratchet the safe-time floor
    // from it (docs/design/safe-time-floor.md). The builder set 1_700_000_000.
    assert_eq!(validated.signing_time_secs, Some(1_700_000_000));

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
    use component_mgr::streaming::process_raw_payload;

    let (signing_key, device_key) = test_keys();
    let crypto = RustCryptoBackend::new();

    let kernel = vec![0xBB; 2048];
    let rootfs = vec![0xCC; 8192];
    let kernel_digest = crypto.sha256(&kernel);
    let rootfs_digest = crypto.sha256(&rootfs);

    let kernel_enc = encrypt_payload(&kernel, &device_key);
    let rootfs_enc = encrypt_payload(&rootfs, &device_key);

    let manifest = MultiComponentBuilder::new()
        .signing_time(1_700_000_000)
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
    use component_mgr::streaming::process_raw_payload;

    let (signing_key, _) = test_keys();
    let crypto = RustCryptoBackend::new();

    let payload = vec![0x42u8; 4096];
    let digest = crypto.sha256(&payload);

    let manifest = ImageManifestBuilder::new()
        .signing_time(1_700_000_000)
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
        .signing_time(1_700_000_000)
        .component_id(vec!["vm1".to_string(), "rootfs.img".to_string()])
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
        .signing_time(1_700_000_000)
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
        .signing_time(1_700_000_000)
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
        .signing_time(1_700_000_000)
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
        .signing_time(1_700_000_000)
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
        .signing_time(1_700_000_000)
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
        Bank::A,
    )
    .await;

    assert!(result.is_err());
}

// =============================================================================
// PULL path: content-addressed fetch + install (fetch_and_install_component)
// =============================================================================

/// Minimal raw-HTTP/1.1 blob server on 127.0.0.1 for the pull tests. Serves the
/// single blob for any path; honours `Range: bytes=N-` with a 206 so the resume
/// path is at least wire-exercisable. Returns the base URL.
async fn serve_blob(blob: Vec<u8>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => return,
            };
            let blob = blob.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let start = req
                    .lines()
                    .find_map(|l| l.strip_prefix("Range: bytes="))
                    .and_then(|r| r.split('-').next())
                    .and_then(|s| s.trim().parse::<usize>().ok())
                    .filter(|s| *s <= blob.len());
                let (line, body): (&str, &[u8]) = match start {
                    Some(s) => ("206 Partial Content", &blob[s..]),
                    None => ("200 OK", &blob[..]),
                };
                let head = format!(
                    "HTTP/1.1 {line}\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body).await;
                let _ = sock.flush().await;
            });
        }
    });
    format!("http://{addr}/")
}

/// Build a manifest-only L2 envelope whose payload is a *remote* content-
/// addressed blob (no integrated payload) — the pull shape.
fn pull_manifest(
    signing_key: &CoseKey,
    inner_digest: &[u8],
    inner_size: u64,
    blob_uri: &str,
    encryption_info: Option<&[u8]>,
) -> Vec<u8> {
    let mut b = ImageManifestBuilder::new()
        .signing_time(1_700_000_000)
        .component_id(vec!["vm1".to_string()])
        .sequence_number(1)
        .security_version(1)
        .payload_digest(inner_digest, inner_size)
        .payload_uri(blob_uri.to_string())
        .text_version("1.0.0");
    if let Some(ei) = encryption_info {
        b = b.encryption_info(ei);
    }
    b.build(signing_key).unwrap()
}

#[tokio::test]
async fn pull_fetch_install_unencrypted() {
    let (signing_key, _) = test_keys();
    let crypto = RustCryptoBackend::new();

    // Unencrypted ⇒ fetched bytes == installed image ⇒ outer == inner digest.
    let payload = vec![0x42u8; 4096];
    let digest = crypto.sha256(&payload);
    let blob_uri = format!("blobs/{}", hex::encode(digest));

    let base = serve_blob(payload.clone()).await;
    let puller = Puller::new(&base, &signing_key.public_key_bytes()).unwrap();
    let envelope = pull_manifest(&signing_key, &digest, payload.len() as u64, &blob_uri, None);

    let tmp = tempfile::tempdir().unwrap();
    let bank = tmp.path().join("rootfs.img");
    let (size, hash) = component_mgr::streaming::fetch_and_install_component(
        &puller,
        &blob_uri,
        payload.len() as u64,
        &envelope,
        0,
        None,
        &digest,
        file_writer(&bank),
        tmp.path(),
    )
    .await
    .unwrap();

    assert_eq!(size, 4096);
    assert_eq!(hash.as_slice(), digest.as_slice());
    assert_eq!(std::fs::read(&bank).unwrap(), payload);
    // Staged ciphertext is removed on success.
    let staged = tmp.path().join(format!("cas-{}.part", hex::encode(digest)));
    assert!(
        !staged.exists(),
        "staged blob should be cleaned up after install"
    );
}

#[tokio::test]
async fn pull_fetch_install_encrypted() {
    let (signing_key, device_key) = test_keys();
    let crypto = RustCryptoBackend::new();

    let plaintext = vec![0xABu8; 8192];
    let inner = crypto.sha256(&plaintext); // image_digest (plaintext)
    let encrypted = encrypt_payload(&plaintext, &device_key);
    let outer = crypto.sha256(&encrypted.ciphertext); // content-address (ciphertext)
    assert_ne!(
        outer.as_slice(),
        inner.as_slice(),
        "outer (ciphertext) and inner (plaintext) digests must differ"
    );
    let blob_uri = format!("blobs/{}", hex::encode(outer));

    let base = serve_blob(encrypted.ciphertext.clone()).await;
    let puller = Puller::new(&base, &signing_key.public_key_bytes()).unwrap();
    let envelope = pull_manifest(
        &signing_key,
        &inner,
        plaintext.len() as u64,
        &blob_uri,
        Some(&encrypted.encryption_info),
    );

    let key_unwrap: std::sync::Arc<dyn sumo_onboard::decryptor::KeyUnwrap + Send + Sync> =
        std::sync::Arc::new(OwnedInMemoryUnwrap {
            device_key_cbor: device_key.to_cose_key_bytes(),
        });

    let tmp = tempfile::tempdir().unwrap();
    let bank = tmp.path().join("rootfs.img");
    let (size, hash) = component_mgr::streaming::fetch_and_install_component(
        &puller,
        &blob_uri,
        encrypted.ciphertext.len() as u64, // OUTER size (what we fetch)
        &envelope,
        0,
        Some(key_unwrap),
        &inner,
        file_writer(&bank),
        tmp.path(),
    )
    .await
    .unwrap();

    assert_eq!(size, 8192);
    assert_eq!(hash.as_slice(), inner.as_slice());
    assert_eq!(std::fs::read(&bank).unwrap(), plaintext);
}

#[tokio::test]
async fn pull_rejects_content_address_mismatch() {
    let (signing_key, _) = test_keys();
    let crypto = RustCryptoBackend::new();

    let payload = vec![0x42u8; 4096];
    let digest = crypto.sha256(&payload);
    let blob_uri = format!("blobs/{}", hex::encode(digest));

    // Server returns TAMPERED bytes — sha won't match the content-address in
    // the (signed) URI, so the fetch must be rejected before any install.
    let mut tampered = payload.clone();
    tampered[0] ^= 0xFF;
    let base = serve_blob(tampered).await;
    let puller = Puller::new(&base, &signing_key.public_key_bytes()).unwrap();
    let envelope = pull_manifest(&signing_key, &digest, payload.len() as u64, &blob_uri, None);

    let tmp = tempfile::tempdir().unwrap();
    let res = component_mgr::streaming::fetch_and_install_component(
        &puller,
        &blob_uri,
        payload.len() as u64,
        &envelope,
        0,
        None,
        &digest,
        file_writer(&tmp.path().join("rootfs.img")),
        tmp.path(),
    )
    .await;

    assert!(
        res.is_err(),
        "tampered CDN content must be rejected at the content-address check"
    );
}

#[tokio::test]
async fn pull_rejects_non_content_addressed_uri() {
    let (signing_key, _) = test_keys();
    let crypto = RustCryptoBackend::new();

    let payload = vec![0x42u8; 1024];
    let digest = crypto.sha256(&payload);
    let blob_uri = "blobs/firmware.bin"; // NOT content-addressed

    let base = serve_blob(payload.clone()).await;
    let puller = Puller::new(&base, &signing_key.public_key_bytes()).unwrap();
    let envelope = pull_manifest(&signing_key, &digest, payload.len() as u64, blob_uri, None);

    let tmp = tempfile::tempdir().unwrap();
    let res = component_mgr::streaming::fetch_and_install_component(
        &puller,
        blob_uri,
        payload.len() as u64,
        &envelope,
        0,
        None,
        &digest,
        file_writer(&tmp.path().join("rootfs.img")),
        tmp.path(),
    )
    .await;

    assert!(
        res.is_err(),
        "non-content-addressed uri must be rejected (outer integrity unverifiable)"
    );
}

// =============================================================================
// L1 campaign walk: resolve_campaign_dependencies
// =============================================================================

/// Build a minimal, signed L2 image envelope (integrated payload) for use as a
/// campaign dependency.
fn l2_envelope(signing_key: &CoseKey, component: &str, payload: &[u8]) -> Vec<u8> {
    let crypto = RustCryptoBackend::new();
    let digest = crypto.sha256(payload);
    ImageManifestBuilder::new()
        .signing_time(1_700_000_000)
        .component_id(vec![component.to_string()])
        .sequence_number(1)
        .security_version(1)
        .payload_digest(&digest, payload.len() as u64)
        .payload_uri("#firmware".to_string())
        .integrated_payload("#firmware".to_string(), payload.to_vec())
        .text_version("1.0.0")
        .build(signing_key)
        .unwrap()
}

#[tokio::test]
async fn campaign_resolves_integrated_and_remote_deps() {
    let (signing_key, _) = test_keys();
    let crypto = RustCryptoBackend::new();

    let l2_a = l2_envelope(&signing_key, "vm1", &[0x11u8; 256]); // integrated in L1
    let l2_b = l2_envelope(&signing_key, "vm2", &[0x22u8; 256]); // remote, content-addressed
    let l2_b_uri = format!("manifests/{}", hex::encode(crypto.sha256(&l2_b)));

    let l1 = CampaignBuilder::new()
        .signing_time(1_700_000_000)
        .sequence_number(1)
        .add_integrated_image("dep-a".to_string(), &l2_a)
        .add_image(l2_b_uri, &l2_b)
        .build(&signing_key)
        .unwrap();

    let base = serve_blob(l2_b.clone()).await;
    let puller = Puller::new(&base, &signing_key.public_key_bytes()).unwrap();

    let envelope = sumo_codec::decode::decode_envelope(&l1).unwrap();
    let manifest = sumo_onboard::manifest::Manifest { envelope };
    let l2s = component_mgr::streaming::resolve_campaign_dependencies(&manifest, &puller)
        .await
        .unwrap();

    assert_eq!(l2s.len(), 2);
    assert_eq!(l2s[0], l2_a, "integrated dep resolved from the signed L1");
    assert_eq!(
        l2s[1], l2_b,
        "remote dep fetched + bound to its content-address"
    );
}

#[tokio::test]
async fn campaign_rejects_content_address_mismatch() {
    let (signing_key, _) = test_keys();
    let crypto = RustCryptoBackend::new();

    let l2_b = l2_envelope(&signing_key, "vm2", &[0x22u8; 256]);
    let l2_b_uri = format!("manifests/{}", hex::encode(crypto.sha256(&l2_b)));

    // The server returns a DIFFERENT, validly-signed L2 — its sha won't match
    // the content-address the signed L1 committed to, so it must be rejected
    // even though it passes signature validation.
    let l2_other = l2_envelope(&signing_key, "vm2", &[0x33u8; 256]);
    let base = serve_blob(l2_other).await;
    let puller = Puller::new(&base, &signing_key.public_key_bytes()).unwrap();

    let l1 = CampaignBuilder::new()
        .signing_time(1_700_000_000)
        .sequence_number(1)
        .add_image(l2_b_uri, &l2_b)
        .build(&signing_key)
        .unwrap();

    let envelope = sumo_codec::decode::decode_envelope(&l1).unwrap();
    let manifest = sumo_onboard::manifest::Manifest { envelope };
    let res = component_mgr::streaming::resolve_campaign_dependencies(&manifest, &puller).await;
    assert!(
        res.is_err(),
        "swapped L2 (sha != content-address) must be rejected"
    );
}

#[tokio::test]
async fn campaign_rejects_non_content_addressed_dep() {
    let (signing_key, _) = test_keys();
    let l2_b = l2_envelope(&signing_key, "vm2", &[0x22u8; 256]);

    let l1 = CampaignBuilder::new()
        .signing_time(1_700_000_000)
        .sequence_number(1)
        .add_image("manifests/latest".to_string(), &l2_b) // NOT content-addressed
        .build(&signing_key)
        .unwrap();

    let base = serve_blob(l2_b.clone()).await;
    let puller = Puller::new(&base, &signing_key.public_key_bytes()).unwrap();

    let envelope = sumo_codec::decode::decode_envelope(&l1).unwrap();
    let manifest = sumo_onboard::manifest::Manifest { envelope };
    let res = component_mgr::streaming::resolve_campaign_dependencies(&manifest, &puller).await;
    assert!(
        res.is_err(),
        "non-content-addressed dependency uri must be rejected"
    );
}

// =============================================================================
// Onboard PULL update route (x-sumo-pull-update) — authorize → resolve → install
// =============================================================================

use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use component_mgr::sovd::authz::{Tier, TieredAuthorizer, TrustedIssuer};
use component_mgr::sovd::pull_update::{pull_update_router, TrustAnchorSource};
use machine_mgr::{
    Capabilities, Component, EntityInfo, EnvelopeStream, FlashCaps, FlashId, FlashSession,
    LifecycleCaps, Machine, MachineRegistry, MachineResult, ResetKind,
};

/// A `Component` stub that records how many envelopes were uploaded + finalized,
/// so the test can assert the pull handler drove the install lifecycle.
struct PullStub {
    id: &'static str,
    bank_set: Option<BankSet>,
    upload_delay_ms: u64,
    uploads: AtomicUsize,
    finalized: AtomicUsize,
    aborted: AtomicUsize,
    caps: Capabilities,
}

impl PullStub {
    fn new(id: &'static str) -> Self {
        Self {
            id,
            bank_set: None,
            upload_delay_ms: 0,
            uploads: AtomicUsize::new(0),
            finalized: AtomicUsize::new(0),
            aborted: AtomicUsize::new(0),
            caps: Capabilities {
                did_store: false,
                flash: Some(FlashCaps {
                    dual_bank: false,
                    supports_rollback: false,
                    supports_trial_boot: false,
                    abortable_after_finalize: false,
                    reset_kind: ResetKind::Local,
                }),
                lifecycle: Some(LifecycleCaps {
                    restartable: false,
                    has_runtime_state: false,
                }),
                hsm: None,
                dtcs: false,
                clear_dtcs: false,
            },
        }
    }
}

impl PullStub {
    fn with_bank_set(mut self, set: BankSet) -> Self {
        self.bank_set = Some(set);
        self
    }
    fn with_upload_delay_ms(mut self, ms: u64) -> Self {
        self.upload_delay_ms = ms;
        self
    }
}

#[async_trait]
impl Component for PullStub {
    fn id(&self) -> &str {
        self.id
    }
    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }
    fn bank_set(&self) -> Option<BankSet> {
        self.bank_set
    }
    async fn start_install(&self) -> MachineResult<FlashSession> {
        Ok(FlashSession {
            id: FlashId::new("pull-test"),
            target_bank: None,
            max_chunk_size: 65536,
        })
    }
    async fn set_install_source(&self, _source: machine_mgr::InstallSource) -> MachineResult<()> {
        Ok(())
    }
    async fn upload_envelope(
        &self,
        _id: &FlashId,
        mut stream: EnvelopeStream,
    ) -> MachineResult<String> {
        use futures::StreamExt;
        if self.upload_delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(self.upload_delay_ms)).await;
        }
        let mut total = 0usize;
        while let Some(chunk) = stream.next().await {
            total += chunk.expect("stream chunk").len();
        }
        assert!(total > 0, "uploaded envelope must be non-empty");
        self.uploads.fetch_add(1, Ordering::SeqCst);
        Ok(format!("part-{total}"))
    }
    async fn finalize_install(&self, _id: &FlashId) -> MachineResult<()> {
        self.finalized.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn abort_install(&self, _id: &FlashId) -> MachineResult<()> {
        self.aborted.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// A deterministic ES256 issuer keypair (no RNG) for the authz token.
fn issuer_keys() -> (jsonwebtoken::EncodingKey, jsonwebtoken::DecodingKey) {
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    let mut scalar = [0u8; 32];
    scalar[31] = 9;
    let sk = SigningKey::from_bytes(&p256::FieldBytes::from(scalar)).unwrap();
    let priv_pem = sk.to_pkcs8_pem(LineEnding::LF).unwrap();
    let pub_pem = sk
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    (
        jsonwebtoken::EncodingKey::from_ec_pem(priv_pem.as_bytes()).unwrap(),
        jsonwebtoken::DecodingKey::from_ec_pem(pub_pem.as_bytes()).unwrap(),
    )
}

/// Mint an ES256 token for issuer `iss`, audience `aud`, carrying `scope`.
fn mint_token(enc: &jsonwebtoken::EncodingKey, iss: &str, aud: &str, scope: &str) -> String {
    use jsonwebtoken::{encode, Algorithm, Header};
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(iss.to_string());
    let claims = serde_json::json!({
        "sub": "operator", "iss": iss, "aud": aud,
        "exp": 9_999_999_999u64, "scope": scope,
    });
    encode(&header, &claims, enc).unwrap()
}

/// An L1 campaign with one integrated + one remote (content-addressed)
/// dependency, served from a mock CAS. Returns (l1_bytes, cas_base_url,
/// trust_anchor).
async fn campaign_fixture() -> (Vec<u8>, String, Vec<u8>) {
    let (signing_key, _) = test_keys();
    let crypto = RustCryptoBackend::new();
    let l2_a = l2_envelope(&signing_key, "vm1", &[0x11u8; 256]);
    let l2_b = l2_envelope(&signing_key, "vm1", &[0x22u8; 256]);
    let l2_b_uri = format!("manifests/{}", hex::encode(crypto.sha256(&l2_b)));
    let l1 = CampaignBuilder::new()
        .signing_time(1_700_000_000)
        .sequence_number(1)
        .add_integrated_image("dep-a".to_string(), &l2_a)
        .add_image(l2_b_uri, &l2_b)
        .build(&signing_key)
        .unwrap();
    let base = serve_blob(l2_b).await;
    (l1, base, signing_key.public_key_bytes())
}

fn operational_authorizer(dec: jsonwebtoken::DecodingKey) -> TieredAuthorizer {
    TieredAuthorizer::new(vec![TrustedIssuer {
        id: "onboard".into(),
        audience: "rig-1".into(),
        key: dec,
        ceiling: Tier::Operational,
    }])
}

/// Register `stubs` in a MachineRegistry rooted at a vehicle entity.
fn pull_machine(stubs: Vec<Arc<dyn Component>>) -> Arc<dyn Machine> {
    let mut b = MachineRegistry::builder(EntityInfo {
        id: "vehicle".into(),
        name: "vehicle".into(),
        entity_type: "vehicle".into(),
        description: None,
        href: "/vehicle/v1".into(),
        status: None,
    });
    for s in stubs {
        b = b.with_arc(s);
    }
    Arc::new(b.build())
}

/// The composed pull-update router over `stubs` + a Tiered authorizer.
fn pull_router(
    stubs: Vec<Arc<dyn Component>>,
    authz: TieredAuthorizer,
    trust_anchor: Vec<u8>,
) -> axum::Router {
    let anchor: TrustAnchorSource = Arc::new(move || Some(trust_anchor.clone()));
    pull_update_router(pull_machine(stubs), Arc::new(authz), anchor)
}

fn pull_body(component: Option<&str>, l1: &[u8], cas_base_url: &str) -> String {
    use base64::Engine;
    serde_json::to_string(&serde_json::json!({
        "component": component,
        "l1_base64": base64::engine::general_purpose::STANDARD.encode(l1),
        "cas_base_url": cas_base_url,
    }))
    .unwrap()
}

const PULL_PATH: &str = "/vehicle/v1/operations/x-sumo-pull-update/executions";

/// POST the pull op; returns (status, Location header, body bytes).
async fn post_pull(
    router: &axum::Router,
    bearer: Option<&str>,
    body: String,
) -> (axum::http::StatusCode, Option<String>, bytes::Bytes) {
    use tower::ServiceExt;
    let mut req = axum::http::Request::builder()
        .method("POST")
        .uri(PULL_PATH)
        .header("content-type", "application/json");
    if let Some(b) = bearer {
        req = req.header("authorization", b);
    }
    let resp = router
        .clone()
        .oneshot(req.body(axum::body::Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let location = resp
        .headers()
        .get(axum::http::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, location, bytes)
}

/// Poll the execution status URL until it leaves Running.
async fn poll_execution(router: &axum::Router, location: &str) -> sovd_core::OperationExecution {
    use tower::ServiceExt;
    for _ in 0..500 {
        let resp = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri(location)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let exec: sovd_core::OperationExecution = serde_json::from_slice(&bytes).unwrap();
        if !matches!(exec.status, sovd_core::OperationStatus::Running) {
            return exec;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!("execution never left Running");
}

#[tokio::test]
async fn pull_update_installs_campaign_under_operational_token() {
    let (l1, base, trust_anchor) = campaign_fixture().await;
    let (enc, dec) = issuer_keys();
    let bearer = format!(
        "Bearer {}",
        mint_token(&enc, "onboard", "rig-1", "component:vm1 update:execute")
    );

    let stub = Arc::new(PullStub::new("vm1"));
    let router = pull_router(
        vec![stub.clone()],
        operational_authorizer(dec),
        trust_anchor,
    );

    let (status, location, _) =
        post_pull(&router, Some(&bearer), pull_body(Some("vm1"), &l1, &base)).await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED);
    let exec = poll_execution(&router, &location.expect("Location header")).await;
    assert!(
        matches!(exec.status, sovd_core::OperationStatus::Completed),
        "status = {:?}, error = {:?}",
        exec.status,
        exec.error
    );
    // Both deps (integrated + remote content-addressed) target vm1 — each is
    // its own install session: two uploads, two finalizes.
    assert_eq!(
        stub.uploads.load(Ordering::SeqCst),
        2,
        "both deps installed"
    );
    assert_eq!(stub.finalized.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn pull_update_rejects_without_token() {
    let (l1, base, trust_anchor) = campaign_fixture().await;
    let (_enc, dec) = issuer_keys();

    let stub = Arc::new(PullStub::new("vm1"));
    let router = pull_router(
        vec![stub.clone()],
        operational_authorizer(dec),
        trust_anchor,
    );

    let (status, _, _) = post_pull(&router, None, pull_body(Some("vm1"), &l1, &base)).await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    assert_eq!(
        stub.uploads.load(Ordering::SeqCst),
        0,
        "nothing installed when unauthorized"
    );
}

#[tokio::test]
async fn pull_update_rejects_token_without_update_scope() {
    let (l1, base, trust_anchor) = campaign_fixture().await;
    let (enc, dec) = issuer_keys();
    // Token has the component scope but NOT update:execute.
    let bearer = format!(
        "Bearer {}",
        mint_token(&enc, "onboard", "rig-1", "component:vm1 data:read")
    );

    let stub = Arc::new(PullStub::new("vm1"));
    let router = pull_router(
        vec![stub.clone()],
        operational_authorizer(dec),
        trust_anchor,
    );

    let (status, _, _) =
        post_pull(&router, Some(&bearer), pull_body(Some("vm1"), &l1, &base)).await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    assert_eq!(stub.uploads.load(Ordering::SeqCst), 0);
}

/// An L1 campaign whose deps are ALL integrated (no CAS traffic), one
/// integrated L2 per target component id.
fn campaign_integrated(signing: &CoseKey, targets: &[&str]) -> Vec<u8> {
    let mut b = CampaignBuilder::new()
        .signing_time(1_700_000_000)
        .sequence_number(1);
    for (i, t) in targets.iter().enumerate() {
        let l2 = l2_envelope(signing, t, &[0x30 + i as u8; 128]);
        b = b.add_integrated_image(format!("dep-{i}"), &l2);
    }
    b.build(signing).unwrap()
}

/// No CAS is contacted for integrated-only campaigns — a dead base URL proves it.
const DEAD_CAS: &str = "http://127.0.0.1:9/";

#[tokio::test]
async fn pull_update_dispatches_each_dep_to_its_component() {
    let (signing, _) = test_keys();
    let l1 = campaign_integrated(&signing, &["vm1", "vm2"]);
    let (enc, dec) = issuer_keys();
    let bearer = format!(
        "Bearer {}",
        mint_token(
            &enc,
            "onboard",
            "rig-1",
            "component:vm1 component:vm2 update:execute"
        )
    );

    let vm1 = Arc::new(PullStub::new("vm1"));
    let vm2 = Arc::new(PullStub::new("vm2"));
    let router = pull_router(
        vec![vm1.clone(), vm2.clone()],
        operational_authorizer(dec),
        signing.public_key_bytes(),
    );

    let (status, location, _) =
        post_pull(&router, Some(&bearer), pull_body(None, &l1, DEAD_CAS)).await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED);
    let exec = poll_execution(&router, &location.unwrap()).await;
    assert!(
        matches!(exec.status, sovd_core::OperationStatus::Completed),
        "status = {:?}, error = {:?}",
        exec.status,
        exec.error
    );
    // One session per component: each stub saw its own upload + finalize.
    assert_eq!(vm1.uploads.load(Ordering::SeqCst), 1);
    assert_eq!(vm1.finalized.load(Ordering::SeqCst), 1);
    assert_eq!(vm2.uploads.load(Ordering::SeqCst), 1);
    assert_eq!(vm2.finalized.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn pull_update_rejects_bad_l1_signature() {
    let (signing, _) = test_keys();
    let l1 = campaign_integrated(&signing, &["vm1"]);
    let (enc, dec) = issuer_keys();
    let bearer = format!(
        "Bearer {}",
        mint_token(&enc, "onboard", "rig-1", "component:vm1 update:execute")
    );

    // The device pins a DIFFERENT sw-authority than the campaign's signer.
    let other_anchor = keygen::generate_signing_key(keygen::ES256)
        .unwrap()
        .public_key_bytes();
    let stub = Arc::new(PullStub::new("vm1"));
    let router = pull_router(
        vec![stub.clone()],
        operational_authorizer(dec),
        other_anchor,
    );

    let (status, _, _) = post_pull(&router, Some(&bearer), pull_body(None, &l1, DEAD_CAS)).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(
        stub.uploads.load(Ordering::SeqCst),
        0,
        "an unsigned/mis-signed L1 must never reach a component"
    );
}

#[tokio::test]
async fn pull_update_rejects_garbage_and_non_campaign() {
    let (signing, _) = test_keys();
    let (enc, dec) = issuer_keys();
    let bearer = format!(
        "Bearer {}",
        mint_token(&enc, "onboard", "rig-1", "component:vm1 update:execute")
    );
    let stub = Arc::new(PullStub::new("vm1"));
    let router = pull_router(
        vec![stub.clone()],
        operational_authorizer(dec),
        signing.public_key_bytes(),
    );

    // Garbage base64.
    let body = r#"{"l1_base64":"!!!not-base64!!!","cas_base_url":"http://127.0.0.1:9/"}"#;
    let (status, _, _) = post_pull(&router, Some(&bearer), body.to_string()).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

    // A plain (signed) L2 is not a campaign — no dependencies.
    let l2 = l2_envelope(&signing, "vm1", &[0x77u8; 64]);
    let (status, _, _) = post_pull(&router, Some(&bearer), pull_body(None, &l2, DEAD_CAS)).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(stub.uploads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn pull_update_wrong_bank_set_target_is_415() {
    let (signing, _) = test_keys();
    let l1 = campaign_integrated(&signing, &["vm2"]);
    let (enc, dec) = issuer_keys();
    let bearer = format!(
        "Bearer {}",
        mint_token(&enc, "onboard", "rig-1", "component:vm2 update:execute")
    );

    // A component registered as "vm2" whose banked storage is the Vm1 slot —
    // the dispatcher's wrong-target check must refuse the envelope (415).
    let stub = Arc::new(PullStub::new("vm2").with_bank_set(BankSet::Vm1));
    let router = pull_router(
        vec![stub.clone()],
        operational_authorizer(dec),
        signing.public_key_bytes(),
    );

    let (status, _, _) = post_pull(&router, Some(&bearer), pull_body(None, &l1, DEAD_CAS)).await;
    assert_eq!(status, axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(stub.uploads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn pull_update_unknown_target_is_404() {
    let (signing, _) = test_keys();
    let l1 = campaign_integrated(&signing, &["vm9"]);
    let (enc, dec) = issuer_keys();
    let bearer = format!(
        "Bearer {}",
        mint_token(&enc, "onboard", "rig-1", "component:vm9 update:execute")
    );
    let stub = Arc::new(PullStub::new("vm1"));
    let router = pull_router(
        vec![stub.clone()],
        operational_authorizer(dec),
        signing.public_key_bytes(),
    );

    let (status, _, _) = post_pull(&router, Some(&bearer), pull_body(None, &l1, DEAD_CAS)).await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    assert_eq!(stub.uploads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn pull_update_component_assertion_mismatch_is_400() {
    let (signing, _) = test_keys();
    let l1 = campaign_integrated(&signing, &["vm2"]);
    let (enc, dec) = issuer_keys();
    let bearer = format!(
        "Bearer {}",
        mint_token(&enc, "onboard", "rig-1", "component:vm2 update:execute")
    );
    let vm2 = Arc::new(PullStub::new("vm2"));
    let router = pull_router(
        vec![vm2.clone()],
        operational_authorizer(dec),
        signing.public_key_bytes(),
    );

    // The caller asserts vm1, but the signed campaign targets vm2 — refuse
    // rather than silently install a subset/mismatch.
    let (status, _, _) = post_pull(
        &router,
        Some(&bearer),
        pull_body(Some("vm1"), &l1, DEAD_CAS),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(vm2.uploads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn pull_update_per_dep_authz_aborts_staged_siblings() {
    let (signing, _) = test_keys();
    let l1 = campaign_integrated(&signing, &["vm1", "vm2"]);
    let (enc, dec) = issuer_keys();
    // Scoped to vm1 ONLY — the vm2 dependency must fail authorization.
    let bearer = format!(
        "Bearer {}",
        mint_token(&enc, "onboard", "rig-1", "component:vm1 update:execute")
    );

    let vm1 = Arc::new(PullStub::new("vm1"));
    let vm2 = Arc::new(PullStub::new("vm2"));
    let router = pull_router(
        vec![vm1.clone(), vm2.clone()],
        operational_authorizer(dec),
        signing.public_key_bytes(),
    );

    let (status, location, _) =
        post_pull(&router, Some(&bearer), pull_body(None, &l1, DEAD_CAS)).await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED);
    let exec = poll_execution(&router, &location.unwrap()).await;
    assert!(
        matches!(exec.status, sovd_core::OperationStatus::Failed),
        "{exec:?}"
    );
    assert!(exec.error.as_deref().unwrap_or("").contains("unauthorized"));
    // vm1 staged first, then vm2's authz failed → vm1's open session aborted;
    // nothing was finalized.
    assert_eq!(vm1.uploads.load(Ordering::SeqCst), 1);
    assert_eq!(vm1.finalized.load(Ordering::SeqCst), 0);
    assert_eq!(vm1.aborted.load(Ordering::SeqCst), 1);
    assert_eq!(vm2.uploads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn pull_update_second_post_while_running_is_409() {
    let (signing, _) = test_keys();
    let l1 = campaign_integrated(&signing, &["vm1"]);
    let (enc, dec) = issuer_keys();
    let bearer = format!(
        "Bearer {}",
        mint_token(&enc, "onboard", "rig-1", "component:vm1 update:execute")
    );
    // Slow upload keeps the first execution Running while the second POSTs.
    let stub = Arc::new(PullStub::new("vm1").with_upload_delay_ms(300));
    let router = pull_router(
        vec![stub.clone()],
        operational_authorizer(dec),
        signing.public_key_bytes(),
    );

    let (status, location, _) =
        post_pull(&router, Some(&bearer), pull_body(None, &l1, DEAD_CAS)).await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED);

    let (status2, _, _) = post_pull(&router, Some(&bearer), pull_body(None, &l1, DEAD_CAS)).await;
    assert_eq!(status2, axum::http::StatusCode::CONFLICT);

    // Unknown execution id → 404.
    use tower::ServiceExt;
    let resp = router
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri(format!("{PULL_PATH}/nope"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);

    // Drain the first execution so the test ends deterministically.
    let exec = poll_execution(&router, &location.unwrap()).await;
    assert!(matches!(exec.status, sovd_core::OperationStatus::Completed));
}
