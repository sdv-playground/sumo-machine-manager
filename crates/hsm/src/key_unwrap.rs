//! HSM-backed implementation of [`sumo_onboard::decryptor::KeyUnwrap`].
//!
//! Lets callers (component-mgr, supernova) plug an `HsmProvider` straight into
//! a `StreamingDecryptor` without ever extracting the device private
//! key. On real HSE this is the only viable path — the EC scalar lives
//! inside the secure element. On SimHsm the work still happens in the
//! host process but routes through the provider trait so the call site
//! is identical.
//!
//! Holds the same `Arc<Mutex<dyn HsmProvider>>` the OTA pipeline already
//! owns — no second trait-object view is required. Each unwrap call
//! locks the mutex briefly to invoke `HsmProvider::unwrap_cek_*`; the
//! lock is dropped before returning.

use std::sync::{Arc, Mutex};

use sumo_onboard::decryptor::KeyUnwrap;
use sumo_onboard::error::Sum2Error;

use crate::{HsmProvider, KeyHandle};

pub struct HsmKeyUnwrap {
    provider: Arc<Mutex<dyn HsmProvider>>,
    handle: KeyHandle,
}

impl HsmKeyUnwrap {
    pub fn new(provider: Arc<Mutex<dyn HsmProvider>>, handle: KeyHandle) -> Self {
        Self { provider, handle }
    }
}

impl KeyUnwrap for HsmKeyUnwrap {
    fn unwrap_cek_a128kw(&self, wrapped_cek: &[u8]) -> Result<Vec<u8>, Sum2Error> {
        let guard = self.provider.lock().map_err(|_| Sum2Error::DecryptFailed)?;
        guard
            .unwrap_cek_a128kw(self.handle, wrapped_cek)
            .map_err(|_| Sum2Error::DecryptFailed)
    }

    fn unwrap_cek_ecdh_es(
        &self,
        ephem_pub: &[u8],
        wrapped_cek: &[u8],
        recipient_protected: &[u8],
    ) -> Result<Vec<u8>, Sum2Error> {
        let guard = self.provider.lock().map_err(|_| Sum2Error::DecryptFailed)?;
        guard
            .unwrap_cek_ecdh_es(self.handle, ephem_pub, wrapped_cek, recipient_protected)
            .map_err(|_| Sum2Error::DecryptFailed)
    }
}
