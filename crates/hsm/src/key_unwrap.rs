//! HSM-backed implementation of [`sumo_onboard::decryptor::KeyUnwrap`].
//!
//! Lets callers (component-mgr, the host) plug an `HsmCryptoProvider` straight
//! into a `StreamingDecryptor` without ever extracting the device private key.
//! On real HSE this is the only viable path — the EC scalar lives inside the
//! secure element. On SimHsm the work still happens in the host process but
//! routes through the crypto trait so the call site is identical.
//!
//! [`HsmKeyUnwrap::from_crypto`] holds an `Arc<dyn HsmCryptoProvider>` (a link-B
//! client, or a SimHsm) and invokes it directly — no mutex, since the crypto
//! trait takes `&self`.

use std::sync::Arc;

use sumo_onboard::decryptor::KeyUnwrap;
use sumo_onboard::error::Sum2Error;

use crate::{HsmCryptoProvider, KeyHandle};

pub struct HsmKeyUnwrap {
    crypto: Arc<dyn HsmCryptoProvider>,
    handle: KeyHandle,
}

impl HsmKeyUnwrap {
    /// Back the unwrap with a crypto-only [`HsmCryptoProvider`] (a link-B client,
    /// or a SimHsm). No mutex: the trait takes `&self`, so the `Arc` is shared
    /// directly. `handle` selects the device key the unwrap runs against (e.g.
    /// [`crate::KeyRole::DeviceDecryption`]).
    pub fn from_crypto(crypto: Arc<dyn HsmCryptoProvider>, handle: KeyHandle) -> Self {
        Self { crypto, handle }
    }
}

impl KeyUnwrap for HsmKeyUnwrap {
    fn unwrap_cek_a128kw(&self, wrapped_cek: &[u8]) -> Result<Vec<u8>, Sum2Error> {
        self.crypto
            .unwrap_cek_a128kw(self.handle, wrapped_cek)
            .map_err(|_| Sum2Error::DecryptFailed)
    }

    fn unwrap_cek_ecdh_es(
        &self,
        ephem_pub: &[u8],
        wrapped_cek: &[u8],
        recipient_protected: &[u8],
    ) -> Result<Vec<u8>, Sum2Error> {
        self.crypto
            .unwrap_cek_ecdh_es(self.handle, ephem_pub, wrapped_cek, recipient_protected)
            .map_err(|_| Sum2Error::DecryptFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HsmError, KeyInfo};

    /// A crypto provider that returns recognizable sentinels (derived from the
    /// handle + inputs) for the two unwrap ops and `NotSupported` for everything
    /// else — enough to prove `from_crypto` routes through `HsmCryptoProvider`
    /// with the configured handle, without standing up a real `SimHsm`.
    struct StubCrypto;

    impl HsmCryptoProvider for StubCrypto {
        fn sign(&self, _h: KeyHandle, _d: &[u8]) -> Result<Vec<u8>, HsmError> {
            Err(HsmError::NotSupported("sign".into()))
        }
        fn verify(&self, _h: KeyHandle, _d: &[u8], _s: &[u8]) -> Result<bool, HsmError> {
            Err(HsmError::NotSupported("verify".into()))
        }
        fn encrypt(&self, _h: KeyHandle, _p: &[u8]) -> Result<Vec<u8>, HsmError> {
            Err(HsmError::NotSupported("encrypt".into()))
        }
        fn decrypt(&self, _h: KeyHandle, _c: &[u8]) -> Result<Vec<u8>, HsmError> {
            Err(HsmError::NotSupported("decrypt".into()))
        }
        fn mac_generate(&self, _h: KeyHandle, _d: &[u8]) -> Result<Vec<u8>, HsmError> {
            Err(HsmError::NotSupported("mac_generate".into()))
        }
        fn mac_verify(&self, _h: KeyHandle, _d: &[u8], _m: &[u8]) -> Result<bool, HsmError> {
            Err(HsmError::NotSupported("mac_verify".into()))
        }
        fn derive(&self, _h: KeyHandle, _c: &[u8], _l: usize) -> Result<Vec<u8>, HsmError> {
            Err(HsmError::NotSupported("derive".into()))
        }
        fn random(&self, _l: usize) -> Result<Vec<u8>, HsmError> {
            Err(HsmError::NotSupported("random".into()))
        }
        fn get_certificate_der(&self, _h: KeyHandle) -> Result<Vec<u8>, HsmError> {
            Err(HsmError::NotSupported("get_certificate_der".into()))
        }
        fn get_public_key_der(&self, _h: KeyHandle) -> Result<Vec<u8>, HsmError> {
            Err(HsmError::NotSupported("get_public_key_der".into()))
        }
        fn get_key_info(&self, _h: KeyHandle) -> Result<KeyInfo, HsmError> {
            Err(HsmError::NotSupported("get_key_info".into()))
        }
        fn unwrap_cek_a128kw(
            &self,
            handle: KeyHandle,
            wrapped_cek: &[u8],
        ) -> Result<Vec<u8>, HsmError> {
            // Sentinel derived from handle + input → proves routing + plumbing.
            let mut out = format!("a128kw:{}:", handle.get()).into_bytes();
            out.extend_from_slice(wrapped_cek);
            Ok(out)
        }
        fn unwrap_cek_ecdh_es(
            &self,
            handle: KeyHandle,
            ephem_pub: &[u8],
            wrapped_cek: &[u8],
            recipient_protected: &[u8],
        ) -> Result<Vec<u8>, HsmError> {
            let mut out = format!("ecdh:{}:", handle.get()).into_bytes();
            out.extend_from_slice(ephem_pub);
            out.extend_from_slice(wrapped_cek);
            out.extend_from_slice(recipient_protected);
            Ok(out)
        }
    }

    #[test]
    fn from_crypto_constructs_and_unwraps_through_the_crypto_provider() {
        let crypto: Arc<dyn HsmCryptoProvider> = Arc::new(StubCrypto);
        let unwrap = HsmKeyUnwrap::from_crypto(crypto, KeyHandle(0x0006));

        // a128kw routes through the crypto provider with the configured handle.
        let got = unwrap.unwrap_cek_a128kw(b"wrapped").unwrap();
        assert_eq!(got, b"a128kw:6:wrapped".to_vec());

        // ecdh-es routes all three byte fields through, in order, with the handle.
        let got = unwrap
            .unwrap_cek_ecdh_es(b"ephem", b"wrapped", b"protected")
            .unwrap();
        assert_eq!(got, b"ecdh:6:ephemwrappedprotected".to_vec());
    }
}
