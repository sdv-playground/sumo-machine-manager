//! SUIT manifest provider — validates RFC 9124 SUIT envelopes via sumo-rs.
//!
//! Uses sumo-onboard's orchestrator for the payload pipeline:
//! fetch → decrypt → decompress → verify → write
//!
//! Two trust stores:
//!
//! - **Provisioning authority** (fixed at startup): validates HSM key envelopes.
//!   This is the authority *over* the HSM — cannot live inside the HSM.
//! - **Software authority** (loaded from HSM after provisioning): validates
//!   firmware SUIT envelopes. None until HSM is provisioned.
//!
//! No file-based fallbacks for software authority or device key.
#![allow(clippy::field_reassign_with_default)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use coset::{iana, CborSerializable, CoseKeyBuilder};
use nv_store::types::BankSet;
use sumo_crypto::{CryptoBackend, RustCryptoBackend};
use sumo_onboard::error::Sum2Error;
use sumo_onboard::orchestrator;
use sumo_onboard::platform::PlatformOps;
use sumo_onboard::Validator;

use crate::manifest_provider::{ManifestError, ManifestProvider, ManifestType, ValidatedFirmware};
use crate::ota::ImageMeta;

/// Translate a `Sum2Error` into a `ManifestError` with an accurate cause.
///
/// `Sum2Error::AuthFailed` is overloaded — it's returned both when the
/// manifest digest doesn't match the authentication wrapper AND when the
/// COSE_Sign1 signature doesn't verify against any trust anchor. To pick
/// the right user-facing message, we decode the envelope and re-check the
/// digest manually: if the digest fails, the error is digest-mismatch;
/// otherwise the signature is the cause.
fn map_sum2_error(
    err: Sum2Error,
    envelope_bytes: &[u8],
    crypto: &RustCryptoBackend,
) -> ManifestError {
    match err {
        Sum2Error::AuthFailed => {
            // Decompose AuthFailed into digest-mismatch vs signature-invalid
            // by re-running the digest check. If decode itself fails we fall
            // back to the generic message.
            if let Ok(envelope) = sumo_codec::decode::decode_envelope(envelope_bytes) {
                let expected = &envelope.authentication.digest.bytes;
                let actual = crypto.sha256(&envelope.manifest_bytes);
                if actual.as_slice() != expected.as_slice() {
                    return ManifestError::SignatureInvalid(format!(
                        "manifest digest mismatch: authentication wrapper expects {} but manifest hashes to {}",
                        hex::encode(expected),
                        hex::encode(actual)
                    ));
                }
            }
            ManifestError::SignatureInvalid("COSE_Sign1 signature verification failed".into())
        }
        Sum2Error::RollbackRejected => {
            ManifestError::ParseError("anti-rollback check failed".into())
        }
        Sum2Error::Revoked => ManifestError::ParseError("trust anchor revoked".into()),
        other => ManifestError::ParseError(format!("{other:?}")),
    }
}

/// URI key for the integrated firmware payload inside the SUIT envelope.
const INTEGRATED_PAYLOAD_KEY: &str = "#firmware";

/// Build the factory provisioning authority as COSE_Key CBOR bytes.
/// Uses the P-256 generator point G (scalar=1) — the well-known factory signing key.
pub fn factory_provisioning_authority() -> Vec<u8> {
    let pub_key = &hsm::payload::FACTORY_SIGNING_PUBLIC;
    let x = &pub_key[1..33];
    let y = &pub_key[33..65];
    CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x.to_vec(), y.to_vec())
        .algorithm(iana::Algorithm::ES256)
        .build()
        .to_vec()
        .expect("COSE_Key serialization")
}

pub struct SuitProvider {
    /// Factory signing key — fallback trust anchor for HSM key envelopes.
    factory_authority: Vec<u8>,
    /// Key authority — verifies HSM key envelopes after first provisioning.
    key_authority: Arc<RwLock<Option<Vec<u8>>>>,
    /// Software authority — validates firmware SUIT envelopes.
    software_authority: Arc<RwLock<Option<Vec<u8>>>>,
    /// CEK unwrapper bound to the device key — invokes HSM under the
    /// hood so the EC private scalar never reaches host memory. Old
    /// design held the raw bytes here; the HSE refactor inverted that.
    device_unwrap: Arc<RwLock<Option<Arc<dyn sumo_onboard::decryptor::KeyUnwrap + Send + Sync>>>>,
    /// Deployment-specific component-ID → BankSet aliases. Lets custom
    /// slot names (e.g. "rt") resolve without polluting nv-store's
    /// well-known list.
    component_aliases: HashMap<String, BankSet>,
}

impl SuitProvider {
    pub fn new(factory_authority: Vec<u8>) -> Self {
        Self {
            factory_authority,
            key_authority: Arc::new(RwLock::new(None)),
            software_authority: Arc::new(RwLock::new(None)),
            device_unwrap: Arc::new(RwLock::new(None)),
            component_aliases: HashMap::new(),
        }
    }

    pub fn with_factory_authority() -> Self {
        Self::new(factory_provisioning_authority())
    }

    /// Register deployment-specific component-ID → BankSet mappings
    /// so SUIT manifests with custom component IDs (e.g. `["rt", "firmware"]`)
    /// resolve to the correct NV slot.
    pub fn with_component_aliases(mut self, aliases: HashMap<String, BankSet>) -> Self {
        self.component_aliases = aliases;
        self
    }

    /// Load all trust keys from HSM after provisioning.
    ///
    /// `key_unwrap` is the optional CEK unwrapper bound to the device
    /// key; typically constructed by the caller as
    /// `HsmKeyUnwrap::new(hsm_provider, "device-decrypt")` so the
    /// streaming decryptor can unwrap CEKs without ever seeing the
    /// device's private key bytes.
    pub fn update_keys(
        &self,
        sw_authority: Vec<u8>,
        key_unwrap: Option<Arc<dyn sumo_onboard::decryptor::KeyUnwrap + Send + Sync>>,
        key_authority: Option<Vec<u8>>,
    ) {
        *self.software_authority.write().unwrap() = Some(sw_authority);
        *self.device_unwrap.write().unwrap() = key_unwrap;
        *self.key_authority.write().unwrap() = key_authority;
        tracing::info!("SuitProvider: loaded trust anchors + CEK unwrapper from HSM");
    }

    /// Check if software authority keys have been loaded.
    pub fn has_software_authority(&self) -> bool {
        self.software_authority.read().unwrap().is_some()
    }

    /// Select the trust anchor based on manifest type.
    fn trust_anchor_for(&self, manifest_type: ManifestType) -> Result<Vec<u8>, ManifestError> {
        match manifest_type {
            ManifestType::HsmKeys => Ok(self
                .key_authority
                .read()
                .unwrap()
                .clone()
                .unwrap_or_else(|| self.factory_authority.clone())),
            ManifestType::Firmware => {
                self.software_authority
                    .read()
                    .unwrap()
                    .clone()
                    .ok_or_else(|| {
                        ManifestError::ParseError(
                            "no software authority key — HSM not yet provisioned".into(),
                        )
                    })
            }
        }
    }

    /// Snapshot the CEK unwrapper for use by the streaming decryptor.
    fn current_device_unwrap(
        &self,
    ) -> Option<Arc<dyn sumo_onboard::decryptor::KeyUnwrap + Send + Sync>> {
        self.device_unwrap.read().unwrap().clone()
    }
}

impl SuitProvider {
    /// Validate envelope header only (no payload processing).
    /// Used by the streaming processor which handles the payload separately.
    pub fn validate_header_only(
        &self,
        data: &[u8],
        min_security_ver: u32,
    ) -> Result<ValidatedFirmware, ManifestError> {
        // First pass: extract metadata to determine manifest type.
        // Use provisioning authority for initial parse — if it's firmware,
        // we'll re-validate with software authority.
        let crypto = RustCryptoBackend::new();

        // Peek at component_id to determine manifest type before full validation
        let manifest_type = peek_manifest_type(data)?;
        let trust_anchor = self.trust_anchor_for(manifest_type)?;

        tracing::debug!(
            manifest_type = ?manifest_type,
            trust_anchor_len = trust_anchor.len(),
            "validating envelope"
        );

        // No `add_device_key` here: in component-mgr the streaming flow
        // (validate header + decrypt body separately) doesn't need the
        // raw device key inside the Validator — decryption uses the
        // HSM-backed `KeyUnwrap` via `key_unwrap_for_decryption()`.
        // Only sumo-rs's in-process orchestrator path uses the
        // Validator-attached device_keys.
        let validator = Validator::new(&trust_anchor, None);

        let manifest = validator
            .validate_envelope(data, &crypto, 0)
            .map_err(|e| map_sum2_error(e, data, &crypto))?;

        let secver = manifest.security_version(0).unwrap_or(0);
        if secver < min_security_ver as u64 {
            return Err(ManifestError::RollbackRejected {
                seq: secver,
                min: min_security_ver as u64,
            });
        }

        self.extract_metadata(&manifest, secver)
    }

    /// Extract metadata from a validated manifest (shared by validate and validate_header_only).
    fn extract_metadata(
        &self,
        manifest: &sumo_onboard::manifest::Manifest,
        secver: u64,
    ) -> Result<ValidatedFirmware, ManifestError> {
        let segments = manifest
            .component_id(0)
            .ok_or_else(|| ManifestError::ComponentUnknown("missing component_id".into()))?;

        // Resolve bank_set from the first segment that matches a BankSet,
        // falling back to deployment-registered component aliases.
        let bank_set = segments
            .iter()
            .find_map(|seg| {
                let s = std::str::from_utf8(seg).ok()?;
                BankSet::from_str(s).or_else(|| self.component_aliases.get(s).copied())
            })
            .ok_or_else(|| {
                let comp_str = segments
                    .iter()
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .collect::<Vec<_>>()
                    .join("/");
                ManifestError::ComponentUnknown(comp_str)
            })?;

        // Detect manifest sub-type from component_id path.
        let manifest_type = {
            let seg_strs: Vec<&str> = segments
                .iter()
                .filter_map(|s| std::str::from_utf8(s).ok())
                .collect();
            if seg_strs == ["hsm", "keys"] {
                ManifestType::HsmKeys
            } else {
                ManifestType::Firmware
            }
        };

        let seq = manifest.sequence_number();
        let seq_u32 = if seq > u32::MAX as u64 {
            u32::MAX
        } else {
            seq as u32
        };

        let mut meta = ImageMeta::default();
        meta.fw_seq = seq_u32;
        meta.fw_secver = if secver > u32::MAX as u64 {
            u32::MAX
        } else {
            secver as u32
        };

        let version_display = manifest
            .text_version(0)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("seq-{seq}"));
        copy_to_nv(&version_display, &mut meta.fw_version);

        if let Some(s) = manifest.text_vendor_name(0) {
            copy_to_nv(s, &mut meta.supplier_sw_number);
            copy_to_nv(&version_display, &mut meta.supplier_sw_version);
        }
        if let Some(s) = manifest.text_model_name(0) {
            copy_to_nv(s, &mut meta.system_name);
        }
        if let Some(s) = manifest.text_model_info(0) {
            copy_to_nv(s, &mut meta.ecu_sw_number);
        }
        if let Some(s) = manifest.text_description() {
            copy_to_nv(s, &mut meta.spare_part_number);
        }

        let now = chrono::Utc::now().format("%Y%m%d").to_string();
        copy_to_nv(&now, &mut meta.programming_date);
        copy_to_nv("SOVD-OTA", &mut meta.tester_serial);

        Ok(ValidatedFirmware {
            bank_set,
            manifest_type,
            image_meta: meta,
            image_data: Vec::new(),
            version_display,
            image_sha256: None,
            image_size: None,
            raw_envelope: None,
            streamed_files: Vec::new(),
        })
    }
}

impl ManifestProvider for SuitProvider {
    fn validate(
        &self,
        data: &[u8],
        min_security_ver: u32,
    ) -> Result<ValidatedFirmware, ManifestError> {
        let crypto = RustCryptoBackend::new();

        // Peek at component_id to select trust store
        let manifest_type = peek_manifest_type(data)?;
        let trust_anchor = self.trust_anchor_for(manifest_type)?;

        // No `add_device_key` here: in component-mgr the streaming flow
        // (validate header + decrypt body separately) doesn't need the
        // raw device key inside the Validator — decryption uses the
        // HSM-backed `KeyUnwrap` via `key_unwrap_for_decryption()`.
        // Only sumo-rs's in-process orchestrator path uses the
        // Validator-attached device_keys.
        let validator = Validator::new(&trust_anchor, None);

        // Validate envelope: signature, digest
        let manifest = validator
            .validate_envelope(data, &crypto, 0)
            .map_err(|e| map_sum2_error(e, data, &crypto))?;

        // Check security_version against floor
        let secver = manifest.security_version(0).unwrap_or(0);
        if secver < min_security_ver as u64 {
            return Err(ManifestError::RollbackRejected {
                seq: secver,
                min: min_security_ver as u64,
            });
        }

        let mut validated = self.extract_metadata(&manifest, secver)?;

        // HSM key manifests: pass raw envelope through — HSM handles
        // decrypt/decompress internally (matches production HSM firmware).
        if validated.manifest_type == ManifestType::HsmKeys {
            validated.raw_envelope = Some(data.to_vec());
            return Ok(validated);
        }

        // Determine update type from manifest command sequences
        let has_payload = manifest.has_firmware();

        let image_data = if has_payload {
            // Extract integrated payload for the orchestrator's fetch
            let raw_payload = manifest
                .integrated_payload(INTEGRATED_PAYLOAD_KEY)
                .ok_or_else(|| {
                    ManifestError::ParseError(format!(
                        "manifest has image_digest but no integrated payload at \"{INTEGRATED_PAYLOAD_KEY}\""
                    ))
                })?
                .to_vec();

            // Run the SUIT orchestrator — handles fetch, decrypt, decompress, verify
            let ops = VmPlatformOps::new(raw_payload);
            orchestrator::process_image(&validator, &manifest, &ops, &crypto).map_err(
                |e| match e {
                    Sum2Error::DigestMismatch => ManifestError::DigestMismatch,
                    other => ManifestError::ParseError(format!("orchestrator: {other:?}")),
                },
            )?;

            ops.take_written()
        } else {
            // CRL / policy-only manifest — no payload
            Vec::new()
        };

        validated.image_data = image_data;
        Ok(validated)
    }

    fn validate_header_only(
        &self,
        data: &[u8],
        min_security_ver: u32,
    ) -> Result<ValidatedFirmware, ManifestError> {
        SuitProvider::validate_header_only(self, data, min_security_ver)
    }

    fn software_authority_key(&self) -> Option<Vec<u8>> {
        self.software_authority.read().unwrap().clone()
    }

    fn key_unwrap_for_decryption(
        &self,
    ) -> Option<Arc<dyn sumo_onboard::decryptor::KeyUnwrap + Send + Sync>> {
        self.current_device_unwrap()
    }

    fn update_keys(
        &self,
        sw_authority: Vec<u8>,
        key_unwrap: Option<Arc<dyn sumo_onboard::decryptor::KeyUnwrap + Send + Sync>>,
        key_authority: Option<Vec<u8>>,
    ) {
        SuitProvider::update_keys(self, sw_authority, key_unwrap, key_authority);
    }
}

// ---------------------------------------------------------------------------
// Peek at manifest type from raw envelope bytes
// ---------------------------------------------------------------------------

/// Quick parse of envelope to determine ManifestType from component_id.
/// Does a full decode — used before signature validation to select trust store.
fn peek_manifest_type(data: &[u8]) -> Result<ManifestType, ManifestError> {
    let envelope = sumo_codec::decode::decode_envelope(data)
        .map_err(|e| ManifestError::ParseError(format!("decode envelope: {e:?}")))?;
    let manifest = sumo_onboard::manifest::Manifest { envelope };

    if let Some(segments) = manifest.component_id(0) {
        let seg_strs: Vec<&str> = segments
            .iter()
            .filter_map(|s| std::str::from_utf8(s).ok())
            .collect();
        if seg_strs == ["hsm", "keys"] {
            return Ok(ManifestType::HsmKeys);
        }
    }
    Ok(ManifestType::Firmware)
}

// ---------------------------------------------------------------------------
// VmPlatformOps — PlatformOps for the SUIT orchestrator
// ---------------------------------------------------------------------------

struct VmPlatformOps {
    /// Pre-staged payload (from integrated envelope)
    staged_payload: Vec<u8>,
    /// Accumulated plaintext written by orchestrator
    written: RefCell<Vec<u8>>,
}

impl VmPlatformOps {
    fn new(staged_payload: Vec<u8>) -> Self {
        Self {
            staged_payload,
            written: RefCell::new(Vec::new()),
        }
    }

    fn take_written(self) -> Vec<u8> {
        self.written.into_inner()
    }
}

impl PlatformOps for VmPlatformOps {
    fn fetch(&self, _uri: &str, buf: &mut [u8]) -> Result<usize, Sum2Error> {
        // Payload is pre-staged from the integrated envelope
        let n = self.staged_payload.len().min(buf.len());
        buf[..n].copy_from_slice(&self.staged_payload[..n]);
        Ok(n)
    }

    fn write(&self, _component_id: &[u8], offset: usize, data: &[u8]) -> Result<(), Sum2Error> {
        let mut written = self.written.borrow_mut();
        let end = offset + data.len();
        if written.len() < end {
            written.resize(end, 0);
        }
        written[offset..end].copy_from_slice(data);
        Ok(())
    }

    fn invoke(&self, _component_id: &[u8]) -> Result<(), Sum2Error> {
        // No-op — VM boot happens at ecu_reset, not here
        Ok(())
    }

    fn swap(&self, _comp_a: &[u8], _comp_b: &[u8]) -> Result<(), Sum2Error> {
        // A/B switching handled by ota::install()
        Ok(())
    }

    fn persist_sequence(&self, _component_id: &[u8], _seq: u64) -> Result<(), Sum2Error> {
        // Security version floor managed by ota::commit()
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn copy_to_nv(s: &str, dst: &mut [u8]) {
    let n = s.len().min(dst.len());
    dst[..n].copy_from_slice(&s.as_bytes()[..n]);
}
