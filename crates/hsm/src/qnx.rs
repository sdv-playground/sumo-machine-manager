#[cfg(feature = "crypto")]
use crate::HsmCryptoProvider;
/// QNX HSM provider — stub for real hardware.
///
/// On QNX, the HSM is real hardware accessed via a resource manager
/// (e.g. `/dev/hsm`). The "service" is the HSM firmware itself, which
/// is always running — `start_service`/`stop_service` are no-ops.
///
/// # What QNX implementors need to do
///
/// - `is_provisioned`: read HSM secure storage to check if key slots
///   are populated.
///
/// - `provision`: accept a SUIT envelope containing key material.
///   If HSM is empty (factory floor), write keys without verification.
///   If HSM already has keys, verify the envelope against current
///   key material and reject if `security_version` does not exceed
///   current value (anti-rollback).
///
/// - `list_keys`: enumerate populated key slots from HSM firmware.
///
/// - `start_service`/`stop_service`: likely no-ops since the HSM
///   firmware runs independently. May manage a TCP proxy if needed.
///
/// - `status`: query HSM firmware health, key slot count, etc.
use crate::{HsmError, HsmProvider, HsmStatus, KeyHandle, KeyInfo, KeyRole, ProvisioningState};

pub struct QnxHsm;

impl Default for QnxHsm {
    fn default() -> Self {
        Self::new()
    }
}

impl QnxHsm {
    pub fn new() -> Self {
        Self
    }
}

impl HsmProvider for QnxHsm {
    fn is_provisioned(&self) -> Result<bool, HsmError> {
        Err(HsmError::NotSupported("QNX HSM not implemented".into()))
    }

    fn provision(&mut self, _suit_envelope: &[u8]) -> Result<(), HsmError> {
        Err(HsmError::NotSupported("QNX HSM not implemented".into()))
    }

    fn list_keys(&self) -> Result<Vec<KeyInfo>, HsmError> {
        Err(HsmError::NotSupported("QNX HSM not implemented".into()))
    }

    fn start_service(&mut self) -> Result<u16, HsmError> {
        Err(HsmError::NotSupported("QNX HSM not implemented".into()))
    }

    fn stop_service(&mut self) -> Result<(), HsmError> {
        Err(HsmError::NotSupported("QNX HSM not implemented".into()))
    }

    fn status(&self) -> Result<HsmStatus, HsmError> {
        Err(HsmError::NotSupported("QNX HSM not implemented".into()))
    }

    fn get_public_key(&self, _role: KeyRole) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::NotSupported("QNX HSM not implemented".into()))
    }

    fn provisioning_state(&self) -> Result<ProvisioningState, HsmError> {
        Err(HsmError::NotSupported("QNX HSM not implemented".into()))
    }
}

#[cfg(feature = "crypto")]
impl HsmCryptoProvider for QnxHsm {
    fn sign(&self, _handle: KeyHandle, _data: &[u8]) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::NotSupported(
            "QNX HSM crypto not implemented".into(),
        ))
    }
    fn verify(&self, _handle: KeyHandle, _data: &[u8], _sig: &[u8]) -> Result<bool, HsmError> {
        Err(HsmError::NotSupported(
            "QNX HSM crypto not implemented".into(),
        ))
    }
    fn encrypt(&self, _handle: KeyHandle, _plaintext: &[u8]) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::NotSupported(
            "QNX HSM crypto not implemented".into(),
        ))
    }
    fn decrypt(&self, _handle: KeyHandle, _ciphertext: &[u8]) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::NotSupported(
            "QNX HSM crypto not implemented".into(),
        ))
    }
    fn mac_generate(&self, _handle: KeyHandle, _data: &[u8]) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::NotSupported(
            "QNX HSM crypto not implemented".into(),
        ))
    }
    fn mac_verify(&self, _handle: KeyHandle, _data: &[u8], _mac: &[u8]) -> Result<bool, HsmError> {
        Err(HsmError::NotSupported(
            "QNX HSM crypto not implemented".into(),
        ))
    }
    fn derive(
        &self,
        _handle: KeyHandle,
        _context: &[u8],
        _len: usize,
    ) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::NotSupported(
            "QNX HSM crypto not implemented".into(),
        ))
    }
    fn random(&self, _len: usize) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::NotSupported(
            "QNX HSM crypto not implemented".into(),
        ))
    }
    fn get_certificate_der(&self, _handle: KeyHandle) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::NotSupported(
            "QNX HSM crypto not implemented".into(),
        ))
    }
    fn get_public_key_der(&self, _handle: KeyHandle) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::NotSupported(
            "QNX HSM crypto not implemented".into(),
        ))
    }
    fn get_key_info(&self, _handle: KeyHandle) -> Result<KeyInfo, HsmError> {
        Err(HsmError::NotSupported(
            "QNX HSM crypto not implemented".into(),
        ))
    }
}
