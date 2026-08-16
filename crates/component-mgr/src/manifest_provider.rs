/// Pluggable manifest validation trait.
///
/// Default implementation: [`SuitProvider`](crate::suit_provider::SuitProvider)
/// using sumo-rs for RFC 9124 SUIT envelope validation.
use std::sync::Arc;

use hsm::ivd::IvdFile;
use nv_store::types::BankSet;
use sumo_onboard::decryptor::KeyUnwrap;

use crate::ota::ImageMeta;

/// Manifest sub-type — determines how the payload is handled after validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestType {
    /// Normal firmware image — write to bank (vm1, vm2, hypervisor, hsm).
    Firmware,
    /// HSM key material — route to HsmProvider::provision() with raw envelope.
    HsmKeys,
}

/// Result of successful manifest validation — ready for OTA install.
#[derive(Clone)]
pub struct ValidatedFirmware {
    pub bank_set: BankSet,
    /// Manifest sub-type (firmware image vs HSM key material).
    pub manifest_type: ManifestType,
    pub image_meta: ImageMeta,
    pub image_data: Vec<u8>,
    pub version_display: String,
    /// Pre-computed image SHA-256 (set by streaming path where image is written to disk directly).
    pub image_sha256: Option<[u8; 32]>,
    /// Image size in bytes (set by streaming path).
    pub image_size: Option<u64>,
    /// Raw SUIT envelope bytes — passed through for HSM key manifests
    /// so the HSM provider can handle decrypt/decompress internally.
    pub raw_envelope: Option<Vec<u8>>,
    /// Per-file SHA-256 + size captured by the streaming pipeline as
    /// each payload was decrypted/decompressed/written. Lets the
    /// IVD-sign step build the manifest without re-hashing the staged
    /// bank dir from disk. Empty for non-streaming (in-memory or
    /// header-only) paths — `sign_bank` falls back to a directory walk.
    pub streamed_files: Vec<IvdFile>,
    /// The manifest's signed signing time (`iat`, UNIX seconds), read from the
    /// verified COSE header. A trustworthy lower bound on real time: the device
    /// ratchets its HSM safe-time floor to `max(floor, iat)` on install, so every
    /// accepted update advances the floor even fully offline
    /// (docs/design/safe-time-floor.md). `None` if the manifest carried none.
    pub signing_time_secs: Option<u64>,
    /// Set for an administrative-*disable* manifest (a `suit-directive-disable`
    /// in the shared sequence, no firmware payload): the index of the component
    /// it disables. The upload path enacts it via the component's `Deactivator`
    /// instead of staging a payload. `None` for ordinary firmware and genuine
    /// CRL/policy manifests, which are unaffected.
    pub disable_target: Option<usize>,
}

#[derive(Debug)]
pub enum ManifestError {
    ParseError(String),
    SignatureInvalid(String),
    /// The manifest's signature verified to a trusted root, but its
    /// `security_version` is below the device's anti-rollback floor — the manifest
    /// is discarded. `signing_time_secs` is the manifest's protected, signature-
    /// covered `signing_time` (if present): a trusted lower bound on real time even
    /// though the manifest itself is rejected. The caller ratchets the safe-time
    /// floor from it before propagating the rejection (monotonic → a stale value is
    /// a no-op; see `docs/safe-time-floor.md`).
    RollbackRejected {
        seq: u64,
        min: u64,
        signing_time_secs: Option<u64>,
    },
    DigestMismatch,
    SizeMismatch {
        expected: u64,
        actual: u64,
    },
    ComponentUnknown(String),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManifestError::ParseError(e) => write!(f, "manifest parse error: {e}"),
            ManifestError::SignatureInvalid(e) => write!(f, "signature invalid: {e}"),
            ManifestError::RollbackRejected { seq, min, .. } => {
                write!(f, "rollback rejected: sequence {seq} < minimum {min}")
            }
            ManifestError::DigestMismatch => write!(f, "image digest mismatch"),
            ManifestError::SizeMismatch { expected, actual } => {
                write!(f, "image size mismatch: expected {expected}, got {actual}")
            }
            ManifestError::ComponentUnknown(c) => write!(f, "unknown component: {c}"),
        }
    }
}

/// Trait for manifest validation. Implementors parse and validate an uploaded
/// firmware blob, returning the extracted image and metadata on success.
pub trait ManifestProvider: Send + Sync {
    fn validate(
        &self,
        data: &[u8],
        min_security_ver: u32,
    ) -> Result<ValidatedFirmware, ManifestError>;

    /// Validate envelope header only (auth + manifest, no payload processing).
    /// Used by the streaming upload path which processes the payload separately.
    /// Default implementation falls back to full `validate()`.
    fn validate_header_only(
        &self,
        data: &[u8],
        min_security_ver: u32,
    ) -> Result<ValidatedFirmware, ManifestError> {
        self.validate(data, min_security_ver)
    }

    /// Snapshot the software authority trust anchor for streaming decryptor setup.
    /// Returns owned bytes — callers may hold these across async boundaries.
    fn software_authority_key(&self) -> Option<Vec<u8>> {
        None
    }

    /// Snapshot a CEK unwrapper for the streaming decryptor — typically
    /// an HSM-backed `HsmKeyUnwrap` bound to the device-decrypt key.
    /// Returns None when no decryption key is wired (the streaming
    /// path then fails fast on encrypted payloads).
    ///
    /// Replaces the prior `device_decryption_key() -> Option<Vec<u8>>`
    /// which leaked the raw EC private scalar into host memory — fine
    /// for SimHsm, broken on real HSE where the key never leaves the
    /// secure element.
    fn key_unwrap_for_decryption(&self) -> Option<Arc<dyn KeyUnwrap + Send + Sync>> {
        None
    }

    /// Update trust-anchor keys from HSM after provisioning.
    /// `key_unwrap` is the optional CEK unwrapper bound to the device
    /// key inside the HSM — replaces the old `device_key: Vec<u8>` arg
    /// that extracted raw bytes.
    fn update_keys(
        &self,
        _sw_authority: Vec<u8>,
        _key_unwrap: Option<Arc<dyn KeyUnwrap + Send + Sync>>,
        _key_authority: Option<Vec<u8>>,
    ) {
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_error_display_parse_error() {
        let e = ManifestError::ParseError("bad cbor".into());
        assert_eq!(format!("{e}"), "manifest parse error: bad cbor");
    }

    #[test]
    fn manifest_error_display_signature_invalid() {
        let e = ManifestError::SignatureInvalid("bad sig".into());
        assert_eq!(format!("{e}"), "signature invalid: bad sig");
    }

    #[test]
    fn manifest_error_display_rollback_rejected() {
        let e = ManifestError::RollbackRejected {
            seq: 3,
            min: 5,
            signing_time_secs: None,
        };
        assert_eq!(format!("{e}"), "rollback rejected: sequence 3 < minimum 5");
    }

    #[test]
    fn manifest_error_display_digest_mismatch() {
        let e = ManifestError::DigestMismatch;
        assert_eq!(format!("{e}"), "image digest mismatch");
    }

    #[test]
    fn manifest_error_display_size_mismatch() {
        let e = ManifestError::SizeMismatch {
            expected: 100,
            actual: 50,
        };
        assert_eq!(format!("{e}"), "image size mismatch: expected 100, got 50");
    }

    #[test]
    fn manifest_error_display_component_unknown() {
        let e = ManifestError::ComponentUnknown("os99".into());
        assert_eq!(format!("{e}"), "unknown component: os99");
    }

    #[test]
    fn manifest_type_equality_and_copy() {
        // Ensures Copy + PartialEq derive exists — used by match branches in OTA path.
        let a = ManifestType::Firmware;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_ne!(ManifestType::Firmware, ManifestType::HsmKeys);
    }

    /// Stub provider that returns success with a minimal ValidatedFirmware to
    /// exercise the default trait methods (validate_header_only delegates,
    /// software/device key snapshots default to None, update_keys is a no-op).
    struct StubProvider;
    impl ManifestProvider for StubProvider {
        fn validate(&self, _data: &[u8], _min: u32) -> Result<ValidatedFirmware, ManifestError> {
            Ok(ValidatedFirmware {
                bank_set: BankSet::Vm1,
                manifest_type: ManifestType::Firmware,
                image_meta: ImageMeta::default(),
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

    #[test]
    fn validate_header_only_default_delegates_to_validate() {
        let p = StubProvider;
        let vf = p.validate_header_only(&[], 0).unwrap();
        assert_eq!(vf.bank_set, BankSet::Vm1);
        assert_eq!(vf.version_display, "1.0.0");
    }

    #[test]
    fn key_accessors_default_to_none() {
        let p = StubProvider;
        assert!(p.software_authority_key().is_none());
        assert!(p.key_unwrap_for_decryption().is_none());
    }

    #[test]
    fn update_keys_default_is_noop() {
        // Just verify it doesn't panic.
        let p = StubProvider;
        p.update_keys(vec![1, 2, 3], None, None);
    }
}
