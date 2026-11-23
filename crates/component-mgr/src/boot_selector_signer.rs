//! HSM-backed [`Signer`] for the node boot selector.
//!
//! Replaces the loud `StubSigner` (empty signature / accept-anything) with real
//! ECDSA-P256 signing + verification via the device HSM's `ivd-signing` key —
//! the same device authority that signs per-bank IVD manifests ([`hsm::ivd`]).
//! The selector digest is signed/verified through the `Arc<dyn HsmCryptoProvider>`
//! the node holds (the link-B crypto client).
//!
//! Scope: this makes the *signing* of the (simulated JSON) boot selector real.
//! The real on-medium raw boot-vector layout and the bootloader-side verify are
//! owned by the C/hardware team and get reimplemented when that spec lands; the
//! signing mechanism here (ivd-signing, ECDSA-P256) carries over unchanged.

use std::sync::Arc;

use hsm::{HsmCryptoProvider, KeyRole};
use machine_mgr::system_bank_state::{Signer, SignerError, StubSigner};

/// [`Signer`] that signs/verifies the boot-selector digest with the device
/// HSM's `ivd-signing` key (ECDSA-P256, DER — same key + algorithm as
/// [`hsm::ivd`]; only the signed message differs: here it is the selector's
/// SHA-256 digest rather than the manifest bytes).
pub struct HsmSelectorSigner {
    crypto: Arc<dyn HsmCryptoProvider>,
}

impl HsmSelectorSigner {
    pub fn new(crypto: Arc<dyn HsmCryptoProvider>) -> Self {
        Self { crypto }
    }
}

impl Signer for HsmSelectorSigner {
    fn sign(&self, sha: &[u8; 32]) -> Result<Vec<u8>, SignerError> {
        // The `Signer` trait is infallible. On any HSM error we log loudly and
        // return an empty signature: the resulting blob fails `is_valid` at the
        // next load, so it is rejected and the node falls back to the NV floor —
        // fail-safe rather than persisting an unverifiable boot selection.
        Ok(match self.crypto.sign(KeyRole::IvdSigning.handle(), sha) {
            Ok(sig) => sig,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    key = KeyRole::IvdSigning.key_id(),
                    "boot-selector sign failed — empty signature (blob rejected at next load)"
                );
                Vec::new()
            }
        })
    }

    fn verify(&self, sha: &[u8; 32], sig: &[u8]) -> Result<bool, SignerError> {
        Ok(
            match self.crypto.verify(KeyRole::IvdSigning.handle(), sha, sig) {
                Ok(ok) => ok,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        key = KeyRole::IvdSigning.key_id(),
                        "boot-selector verify failed — rejecting selector"
                    );
                    false
                }
            },
        )
    }
}

/// Build the boot-selector [`Signer`]: HSM-backed when a crypto handle is
/// present, else the loud `StubSigner` (the no-HSM smoke path keeps booting).
/// Keeping the `Some`/`None` choice here makes it unit-testable and the call
/// site a one-liner.
pub fn make_selector_signer(crypto: &Option<Arc<dyn HsmCryptoProvider>>) -> Box<dyn Signer> {
    match crypto {
        Some(c) => Box::new(HsmSelectorSigner::new(c.clone())),
        None => Box::new(StubSigner),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hsm_sim_backend::SimHsm;

    /// vHSM wire alg for EC-P256 keygen, as the protocol numbers it.
    const ALG_ECC_P256: u32 = 0x0021;

    /// A `SimHsm` over a temp keystore with a freshly generated `ivd-signing`
    /// EC-P256 key, as the `Arc<dyn HsmCryptoProvider>` the node holds.
    /// `tempfile::TempDir` is returned so the keystore outlives the HSM.
    fn hsm_with_ivd_key() -> (Arc<dyn HsmCryptoProvider>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let hsm = SimHsm::new(tmp.path().to_path_buf());
        hsm.generate_key(KeyRole::IvdSigning.handle(), ALG_ECC_P256)
            .expect("generate ivd-signing key");
        (Arc::new(hsm), tmp)
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let (hsm, _tmp) = hsm_with_ivd_key();
        let signer = HsmSelectorSigner::new(hsm);
        let sha = [0x11u8; 32];

        let sig = signer.sign(&sha).unwrap();
        assert!(!sig.is_empty(), "HSM sign must produce a real signature");
        assert!(
            signer.verify(&sha, &sig).unwrap(),
            "freshly-signed digest must verify"
        );
    }

    #[test]
    fn verify_rejects_tampered_signature_and_digest() {
        let (hsm, _tmp) = hsm_with_ivd_key();
        let signer = HsmSelectorSigner::new(hsm);
        let sha = [0x22u8; 32];
        let sig = signer.sign(&sha).unwrap();

        // Tampered signature → reject.
        let mut bad_sig = sig.clone();
        *bad_sig.last_mut().unwrap() ^= 0x01;
        assert!(!signer.verify(&sha, &bad_sig).unwrap());

        // Same signature, different digest → reject.
        let mut other = sha;
        other[0] ^= 0x01;
        assert!(!signer.verify(&other, &sig).unwrap());

        // Empty signature (what a failed sign yields) → reject.
        assert!(!signer.verify(&sha, &[]).unwrap());
    }

    #[test]
    fn make_selector_signer_some_is_hsm_backed() {
        let (hsm, _tmp) = hsm_with_ivd_key();
        let signer = make_selector_signer(&Some(hsm));
        let sha = [0x33u8; 32];
        let sig = signer.sign(&sha).unwrap();
        assert!(!sig.is_empty(), "Some(hsm) → real signature");
        assert!(signer.verify(&sha, &sig).unwrap());
    }

    #[test]
    fn make_selector_signer_none_falls_back_to_stub() {
        // No-HSM smoke path: StubSigner signs empty and accepts anything.
        let signer = make_selector_signer(&None);
        let sha = [0x44u8; 32];
        assert!(
            signer.sign(&sha).unwrap().is_empty(),
            "None → StubSigner returns empty signature"
        );
        assert!(
            signer.verify(&sha, &[]).unwrap(),
            "StubSigner accepts (no-op verify)"
        );
    }
}
