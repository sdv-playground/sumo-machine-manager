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
    /// Any HSM error is `Err`: nothing is written with a signature the HSM
    /// did not produce.
    fn sign(&self, sha: &[u8; 32]) -> Result<Vec<u8>, SignerError> {
        self.crypto
            .sign(KeyRole::IvdSigning.handle(), sha)
            .map_err(|e| {
                SignerError::with_source(
                    format!("boot-selector sign with {}", KeyRole::IvdSigning.key_id()),
                    e,
                )
            })
    }

    /// `Ok(false)` for a signature that is not a DER ECDSA-P256 signature —
    /// empty (what a failed sign wrote before signing could fail) or
    /// malformed — decided here without the HSM, and for one the HSM answers
    /// does not verify. Every HSM error is `Err`: a well-formed signature
    /// reaches the HSM, so an error there is the HSM failing to decide, never
    /// a verdict (a backend may report a malformed signature as an error too,
    /// which is why that case never reaches it).
    fn verify(&self, sha: &[u8; 32], sig: &[u8]) -> Result<bool, SignerError> {
        if p256::ecdsa::DerSignature::from_bytes(sig).is_err() {
            return Ok(false);
        }
        self.crypto
            .verify(KeyRole::IvdSigning.handle(), sha, sig)
            .map_err(|e| {
                SignerError::with_source(
                    format!("boot-selector verify with {}", KeyRole::IvdSigning.key_id()),
                    e,
                )
            })
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
    use hsm::{HsmError, KeyHandle, SlotInfo};
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
        assert!(matches!(signer.verify(&sha, &bad_sig), Ok(false)));

        // Same signature, different digest → reject.
        let mut other = sha;
        other[0] ^= 0x01;
        assert!(matches!(signer.verify(&other, &sig), Ok(false)));

        // Empty signature (what a failed sign wrote before signing could
        // fail) → invalid, not an error.
        assert!(matches!(signer.verify(&sha, &[]), Ok(false)));
    }

    /// The sim HSM, with `sign` / `verify` failing while `down` is set, and
    /// its `verify` calls counted.
    struct FlakyHsm {
        inner: SimHsm,
        down: std::sync::atomic::AtomicBool,
        verifies: std::sync::atomic::AtomicUsize,
    }

    impl FlakyHsm {
        fn set_down(&self, down: bool) {
            self.down.store(down, std::sync::atomic::Ordering::SeqCst);
        }
        fn verifies(&self) -> usize {
            self.verifies.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn check(&self) -> Result<(), HsmError> {
            if self.down.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(HsmError::CryptoError("link-b: backend gone".into()));
            }
            Ok(())
        }
    }

    impl HsmCryptoProvider for FlakyHsm {
        fn sign(&self, handle: KeyHandle, data: &[u8]) -> Result<Vec<u8>, HsmError> {
            self.check()?;
            self.inner.sign(handle, data)
        }
        fn verify(&self, handle: KeyHandle, data: &[u8], sig: &[u8]) -> Result<bool, HsmError> {
            self.verifies
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.check()?;
            self.inner.verify(handle, data, sig)
        }
        fn encrypt(&self, handle: KeyHandle, plaintext: &[u8]) -> Result<Vec<u8>, HsmError> {
            self.inner.encrypt(handle, plaintext)
        }
        fn decrypt(&self, handle: KeyHandle, ciphertext: &[u8]) -> Result<Vec<u8>, HsmError> {
            self.inner.decrypt(handle, ciphertext)
        }
        fn mac_generate(&self, handle: KeyHandle, data: &[u8]) -> Result<Vec<u8>, HsmError> {
            self.inner.mac_generate(handle, data)
        }
        fn mac_verify(&self, handle: KeyHandle, data: &[u8], mac: &[u8]) -> Result<bool, HsmError> {
            self.inner.mac_verify(handle, data, mac)
        }
        fn derive(
            &self,
            handle: KeyHandle,
            context: &[u8],
            len: usize,
        ) -> Result<Vec<u8>, HsmError> {
            self.inner.derive(handle, context, len)
        }
        fn random(&self, len: usize) -> Result<Vec<u8>, HsmError> {
            self.inner.random(len)
        }
        fn get_certificate_der(&self, handle: KeyHandle) -> Result<Vec<u8>, HsmError> {
            self.inner.get_certificate_der(handle)
        }
        fn get_public_key_der(&self, handle: KeyHandle) -> Result<Vec<u8>, HsmError> {
            self.inner.get_public_key_der(handle)
        }
        fn get_slot_info(&self, handle: KeyHandle) -> Result<SlotInfo, HsmError> {
            self.inner.get_slot_info(handle)
        }
    }

    fn flaky_hsm() -> (Arc<FlakyHsm>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let inner = SimHsm::new(tmp.path().to_path_buf());
        inner
            .generate_key(KeyRole::IvdSigning.handle(), ALG_ECC_P256)
            .expect("generate ivd-signing key");
        let hsm = FlakyHsm {
            inner,
            down: Default::default(),
            verifies: Default::default(),
        };
        (Arc::new(hsm), tmp)
    }

    #[test]
    fn hsm_error_on_sign_is_err_never_an_empty_signature() {
        let (hsm, _tmp) = flaky_hsm();
        let signer = HsmSelectorSigner::new(hsm.clone());
        hsm.set_down(true);
        assert!(signer.sign(&[0x55u8; 32]).is_err());
    }

    #[test]
    fn hsm_error_on_verify_is_err_not_invalid() {
        let (hsm, _tmp) = flaky_hsm();
        let signer = HsmSelectorSigner::new(hsm.clone());
        let sha = [0x66u8; 32];
        let sig = signer.sign(&sha).unwrap();

        hsm.set_down(true);
        assert!(signer.verify(&sha, &sig).is_err());
        hsm.set_down(false);
        assert!(matches!(signer.verify(&sha, &sig), Ok(true)));
    }

    #[test]
    fn empty_or_malformed_signature_is_invalid_without_asking_the_hsm() {
        let (hsm, _tmp) = flaky_hsm();
        let signer = HsmSelectorSigner::new(hsm.clone());
        let sha = [0x77u8; 32];

        hsm.set_down(true);
        assert!(matches!(signer.verify(&sha, &[]), Ok(false)));
        assert!(matches!(
            signer.verify(&sha, &[0x30, 0x01, 0x00]),
            Ok(false)
        ));
        assert!(matches!(signer.verify(&sha, &[0xA5; 32]), Ok(false)));
        assert_eq!(hsm.verifies(), 0, "decided without the HSM");
    }

    #[test]
    fn hsm_down_fails_the_store_and_keeps_its_files_while_an_empty_signature_reads_absent() {
        use machine_mgr::system_bank_state::{
            ComponentEntry, FileSelectorStore, SelectorBlob, SelectorError, SelectorStore,
            Transaction,
        };
        use nv_store::types::Bank;
        use std::collections::BTreeMap;

        let (hsm, _tmp) = flaky_hsm();
        let dir = tempfile::tempdir().expect("tempdir");
        let store =
            FileSelectorStore::new(dir.path(), Box::new(HsmSelectorSigner::new(hsm.clone())));
        let entries = |bank| {
            BTreeMap::from([(
                "vm1".to_string(),
                ComponentEntry::new(bank, BTreeMap::new()),
            )])
        };
        let header = Transaction {
            armed_boot_id: [0; 16],
            trial_boots: 0,
            counted_boot_id: [0; 16],
            resolution: None,
        };
        store.activate(&entries(Bank::A), &header).unwrap();
        store.commit().unwrap();
        let files = |name: &str| std::fs::read(dir.path().join(name)).unwrap();
        let before = (files("primary"), files("secondary"));

        hsm.set_down(true);
        assert!(matches!(
            store.read_primary(),
            Err(SelectorError::Unreadable(_))
        ));
        assert!(store.activate(&entries(Bank::B), &header).is_err());
        assert!(store.commit().is_err());
        assert_eq!((files("primary"), files("secondary")), before);

        // A primary an older build wrote with an empty signature is invalid,
        // decided without the HSM: it reads as absent (and is reseeded).
        let sha = SelectorBlob::compute_sha256(3, &entries(Bank::B), None);
        let legacy = SelectorBlob {
            generation: 3,
            entries: entries(Bank::B),
            transaction: None,
            sha256: sha,
            signature: Vec::new(),
            selectors: None,
        };
        std::fs::write(
            dir.path().join("primary"),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        assert_eq!(store.read_primary().unwrap(), None);
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
