// ===========================================================================
// Declared parts — a bank that knows which parts it holds refuses the rest
// ===========================================================================
use super::super::*;
use crate::manifest_provider::{ManifestError, ManifestProvider, ValidatedFirmware};
use machine_mgr::bank_provider::{BankError, BankProvider};
use machine_mgr::ResetKind;
use nv_store::block::MemBlockDevice;
use nv_store::slots;
use nv_store::store::MIN_NV_DEVICE_SIZE;
use sumo_offboard::image_builder::{ComponentSpec as SuitComponentSpec, MultiComponentBuilder};
use sumo_offboard::keygen;

/// A manifest provider that validates anything — these tests are about what
/// happens AFTER validation, and the SUIT signature is checked elsewhere.
struct CannedManifest;
impl ManifestProvider for CannedManifest {
    fn validate(&self, _d: &[u8], _m: u32) -> Result<ValidatedFirmware, ManifestError> {
        Ok(ValidatedFirmware {
            component_name: "host".into(),
            manifest_type: ManifestType::Firmware,
            image_meta: crate::ota::ImageMeta::default(),
            image_data: Vec::new(),
            version_display: "1.0.0".into(),
            image_sha256: None,
            image_size: None,
            raw_envelope: None,
            streamed_files: Vec::new(),
            signing_time_secs: None,
            disable_target: None,
        })
    }
}

/// A raw-partition-shaped provider: every payload sink is refused with
/// `UnknownPart`, the way `PartitionBankProvider` refuses a name outside its
/// map. Everything else is an unreachable stub.
struct UnknownPartProvider;
impl BankProvider for UnknownPartProvider {
    fn active_bank(&self) -> Bank {
        Bank::A
    }
    fn target_bank(&self) -> Bank {
        Bank::B
    }
    fn prepare_target(&self, _bank: Bank) -> Result<(), BankError> {
        Ok(())
    }
    fn open_payload_writer(
        &self,
        _bank: Bank,
        name: &str,
    ) -> Result<Box<dyn std::io::Write + Send>, BankError> {
        Err(BankError::UnknownPart(name.into()))
    }
    fn seal(
        &self,
        _b: Bank,
        _i: FirmwareIdentity,
        _g: u64,
        _r: &[String],
    ) -> Result<(), BankError> {
        Ok(())
    }
    fn read_installed(&self, _bank: Bank) -> Result<InstalledFirmware, BankError> {
        Err(BankError::NotInstalled)
    }
    fn verify_payload(&self, _b: Bank, name: &str, _s: &[u8; 32]) -> Result<(), BankError> {
        Err(BankError::UnknownPart(name.into()))
    }
    fn activate(&self, _bank: Bank) -> Result<ResetKind, BankError> {
        Ok(ResetKind::RequiresEcuReset)
    }
    fn commit(&self) -> Result<(), BankError> {
        Ok(())
    }
    fn rollback(&self) -> Result<(), BankError> {
        Ok(())
    }
    fn can_persist_disabled_record(&self) -> Result<(), BankError> {
        Err(BankError::Failed("test provider".into()))
    }
    fn write_disabled_record(&self, _bank: Bank, _gen: u64) -> Result<(), BankError> {
        Err(BankError::Failed("test provider".into()))
    }
    fn disabled_record(&self, _bank: Bank) -> Result<Option<u64>, BankError> {
        Ok(None)
    }
}

fn host_backend() -> ComponentBackend<MemBlockDevice> {
    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    nv.write_boot_state(&mut NvBootState::default()).unwrap();
    ComponentBackend::with_options(
        slots::OS,
        Arc::new(Mutex::new(nv)),
        Arc::new(CannedManifest),
        ComponentConfig::default(),
        None,
        None,
        None,
    )
    .with_id("host".into())
}

/// A detached manifest declaring one payload per `part`, addressed to `host`.
fn manifest_for(parts: &[&str]) -> Vec<u8> {
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let mut builder = MultiComponentBuilder::new()
        .signing_time(1_700_000_000)
        .sequence_number(2);
    for (i, part) in parts.iter().enumerate() {
        builder = builder.add_component(SuitComponentSpec {
            id: vec!["host".into(), (*part).into()],
            digest: vec![i as u8 + 1; 32],
            size: 16,
            uri: format!("#{part}"),
            encryption_info: None,
        });
    }
    builder.build(&key).unwrap()
}

fn stream_of(data: Vec<u8>) -> PackageStream {
    Box::pin(futures::stream::iter(vec![Ok::<
        bytes::Bytes,
        Box<dyn std::error::Error + Send + Sync>,
    >(bytes::Bytes::from(data))]))
}

/// The sink-level refusal: a provider with a fixed part map says
/// `UnknownPart`, and the wire must answer 415 — the wrong PACKAGE for this
/// component, not a 500 the operator would read as "retry".
#[tokio::test]
async fn payload_naming_an_undeclared_part_is_refused_with_415() {
    let manifest = manifest_for(&["x"]);
    let backend = host_backend().with_bank_provider(Arc::new(UnknownPartProvider));
    *backend.flash_session.lock().unwrap() = Some(FlashSessionState::AwaitingPayload {
        manifest_bytes: manifest,
        validated: CannedManifest.validate(&[], 0).unwrap(),
        parts: vec![0],
        present: BTreeSet::new(),
    });

    let err = backend
        .handle_payload_upload(stream_of(b"payload bytes".to_vec()), None)
        .await
        .expect_err("a part the bank does not hold must be refused");
    assert_eq!(err.status_code(), 415, "got {err:?}");
    assert!(
        matches!(err, BackendError::UnsupportedMediaType(ref m) if m.contains("open payload sink x")),
        "the refusal names the sink it refused: {err:?}"
    );
}

/// The whole point of declaring parts: the refusal lands at MANIFEST time,
/// before a payload byte crosses the link, and leaves the session exactly
/// where it was — nothing staged, nothing to abort.
#[tokio::test]
async fn manifest_naming_an_undeclared_part_is_refused_before_any_payload() {
    let backend = host_backend().with_declared_parts(["application.img".to_string()]);
    *backend.flash_session.lock().unwrap() = Some(FlashSessionState::AwaitingManifest);

    let err = backend
        .handle_manifest_upload(stream_of(manifest_for(&["x", "kernel"])), None)
        .await
        .expect_err("a manifest naming an undeclared part must be refused");
    assert_eq!(err.status_code(), 415, "got {err:?}");
    assert!(
        matches!(err, BackendError::UnsupportedMediaType(ref m)
                if m == "manifest part 'x' is not a part of bank 'host' \
                         (declared: application.img)"),
        "the refusal names the part, the bank and what the bank DOES hold: {err:?}"
    );
    assert!(
        matches!(
            *backend.flash_session.lock().unwrap(),
            Some(FlashSessionState::AwaitingManifest)
        ),
        "the refused manifest moved nothing — the session still awaits one"
    );

    // A manifest naming only declared parts goes through untouched.
    backend
        .handle_manifest_upload(stream_of(manifest_for(&["application.img"])), None)
        .await
        .expect("a manifest within the declared parts is accepted");
    assert!(
        matches!(
            *backend.flash_session.lock().unwrap(),
            Some(FlashSessionState::AwaitingPayload { .. })
        ),
        "…and the session advanced to awaiting its payload"
    );
}
