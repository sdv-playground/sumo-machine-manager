pub mod payload;
pub mod sim;
/// HSM provider trait and implementations.
///
/// Defines the management interface for Hardware Security Modules.
/// The trait covers lifecycle and provisioning — not the crypto wire
/// protocol (REGISTER, SIGN, VERIFY, etc.), which is handled by the
/// guest-facing HSM service.
///
/// Implementations:
/// - SimHsm: manages vhsm-ssd + file-based keystore (dev/test + QNX host)
/// - QnxHsm: stub for real HSM hardware via QNX resource manager
pub mod types;
pub mod linux {
    //! Backward-compatible re-export. Prefer `hsm::sim::SimHsm`.
    pub use crate::sim::*;
}
#[cfg(feature = "crypto")]
pub mod crypto;
pub mod ivd;
#[cfg(feature = "suit")]
pub mod key_unwrap;
pub mod qnx;

#[cfg(feature = "suit")]
pub use key_unwrap::HsmKeyUnwrap;
pub use types::*;

/// HSM management provider.
///
/// Implementors manage the HSM keystore and service lifecycle.
/// The crypto wire protocol (TCP on the private `vbr-vhsm` bridge) is
/// handled by the underlying service — this trait only covers
/// provisioning and process management.
///
/// # Provisioning model
///
/// Key material arrives as a SUIT envelope (component `["hsm", "keys"]`).
/// - Empty HSM (factory): payload accepted without verification.
/// - Provisioned HSM: envelope verified against current keys,
///   `security_version` must exceed current.
///
/// The key material encoding inside the SUIT payload is opaque to this
/// trait — each implementation unpacks it into its own storage format.
///
/// # For QNX implementors
///
/// On QNX, the "service" is the HSM firmware itself (always running).
/// `start_service`/`stop_service` may be no-ops. Provisioning writes
/// key material to the real secure storage via the QNX resource manager.
pub trait HsmProvider: Send {
    /// Check if the keystore has been provisioned.
    fn is_provisioned(&self) -> Result<bool, HsmError>;

    /// Provision the HSM with key material from a SUIT envelope.
    ///
    /// If the HSM is empty (factory), the payload is accepted without
    /// verification — trust is physical (factory floor).
    ///
    /// If the HSM already has keys, the envelope is verified against
    /// the current key material and `security_version` must exceed
    /// the current value. This prevents rollback to old key sets.
    fn provision(&mut self, suit_envelope: &[u8]) -> Result<(), HsmError>;

    /// List keys currently in the keystore.
    fn list_keys(&self) -> Result<Vec<KeyInfo>, HsmError>;

    /// Start the HSM service so guests can connect via TCP.
    /// Returns the TCP port the service is listening on.
    fn start_service(&mut self) -> Result<u16, HsmError>;

    /// Stop the HSM service.
    fn stop_service(&mut self) -> Result<(), HsmError>;

    /// Check health/status of the HSM subsystem.
    fn status(&self) -> Result<HsmStatus, HsmError>;

    /// Retrieve a public key by role, as COSE_Key CBOR bytes.
    fn get_public_key(&self, role: KeyRole) -> Result<Vec<u8>, HsmError>;

    // get_private_key intentionally removed — private keys never leave
    // the HSM.  Decrypt via unwrap_cek_a128kw / unwrap_cek_ecdh_es;
    // sign via HsmCryptoProvider::sign; CSR-gen via generate_csr (key
    // stays in-HSM).  If you reach for "give me the bytes" you're
    // designing against the HSE model.

    /// Get the current provisioning lifecycle state.
    fn provisioning_state(&self) -> Result<ProvisioningState, HsmError>;

    /// AES-KW unwrap delegated to the HSM. Same semantics as
    /// [`HsmCryptoProvider::unwrap_cek_a128kw`] — exposed on
    /// `HsmProvider` too so the OTA pipeline (which holds the HSM
    /// as `Arc<Mutex<dyn HsmProvider>>` for lifecycle ops) can route
    /// unwrap requests without needing a second trait-object view.
    ///
    /// Default impl returns `NotSupported`; concrete providers override.
    fn unwrap_cek_a128kw(&self, key_id: &str, wrapped_cek: &[u8]) -> Result<Vec<u8>, HsmError> {
        let _ = (key_id, wrapped_cek);
        Err(HsmError::NotSupported(
            "HsmProvider::unwrap_cek_a128kw".into(),
        ))
    }

    /// ECDH-ES+A128KW unwrap delegated to the HSM. See
    /// [`HsmCryptoProvider::unwrap_cek_ecdh_es`] for parameter docs.
    fn unwrap_cek_ecdh_es(
        &self,
        key_id: &str,
        ephem_pub: &[u8],
        wrapped_cek: &[u8],
        recipient_protected: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        let _ = (key_id, ephem_pub, wrapped_cek, recipient_protected);
        Err(HsmError::NotSupported(
            "HsmProvider::unwrap_cek_ecdh_es".into(),
        ))
    }

    /// ECDSA-SHA256 sign delegated to the HSM. Same semantics as
    /// [`HsmCryptoProvider::sign`] — exposed on `HsmProvider` so the
    /// OTA pipeline (which holds the HSM as
    /// `Arc<Mutex<dyn HsmProvider>>`) can self-sign bank dirs via the
    /// IVD machinery without needing a second trait-object view.
    fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        let _ = (key_id, data);
        Err(HsmError::NotSupported("HsmProvider::sign".into()))
    }

    /// Arm an in-band ENROLL_ASSISTED for `vm_id`. Used by vm-mgr at
    /// OTA install time: after staging a guest's firmware bank, the
    /// orchestrator calls this so the daemon will accept the guest's
    /// next HELLO → ENROLL_ASSISTED handshake. No secret bytes — the
    /// guest's identity is the source IP, configured in the daemon's
    /// `--ip-map` resolver.
    ///
    /// `ttl_secs = None` means no expiry (operator-managed lifecycle).
    /// Re-arming an already-armed vm_id replaces the entry (resets the
    /// clock); re-arming after a successful consume re-enables enrolment
    /// (used for cert rotation).
    ///
    /// Default impl returns `NotSupported`; concrete providers
    /// (SimHsm today; HSE-backed later) override.
    fn arm_enrollment(&mut self, vm_id: &str, ttl_secs: Option<u64>) -> Result<(), HsmError> {
        let _ = (vm_id, ttl_secs);
        Err(HsmError::NotSupported("HsmProvider::arm_enrollment".into()))
    }

    /// True if `vm_id` has completed an ENROLL_ASSISTED at least once
    /// (the daemon recorded an `EnrolledRecord` in bootstrap.yaml).
    /// Host-side auto-arm paths (supernova startup, recovery scripts)
    /// gate on this to avoid re-arming cert-bound vm_ids — re-arming
    /// re-opens an IP-spoof rotation window for a vm that's already
    /// happily running with a valid cert.
    ///
    /// To intentionally re-arm (e.g. cert compromise → operator-driven
    /// rotation), call `clear_enrolled` first.
    ///
    /// Default impl returns `NotSupported`.
    fn is_enrolled(&self, vm_id: &str) -> Result<bool, HsmError> {
        let _ = vm_id;
        Err(HsmError::NotSupported("HsmProvider::is_enrolled".into()))
    }

    /// Forcibly forget that `vm_id` has enrolled. After this returns,
    /// a subsequent `arm_enrollment` is allowed by the auto-arm guard.
    /// Used by recovery / rotation flows; should NOT be called as part
    /// of normal install (use the OTA `commit_flash` hook instead,
    /// which arm_enrollments directly).
    ///
    /// Default impl returns `NotSupported`.
    fn clear_enrolled(&mut self, vm_id: &str) -> Result<bool, HsmError> {
        let _ = vm_id;
        Err(HsmError::NotSupported("HsmProvider::clear_enrolled".into()))
    }

    /// ECDSA-SHA256 verify delegated to the HSM. Mirror of `sign`,
    /// used by `sumo-verify` on the management path.
    fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> Result<bool, HsmError> {
        let _ = (key_id, data, signature);
        Err(HsmError::NotSupported("HsmProvider::verify".into()))
    }
}

/// Crypto operations — keys never leave the HSM.
///
/// Guest-facing services (vhsm-ssd) delegate all crypto here.
/// On production hardware, the implementation routes to the HSM
/// firmware — private keys never leave the secure boundary.
///
/// In simulation mode, `SimHsm` reads PEM keys from the
/// keystore and performs operations in software via RustCrypto.
pub trait HsmCryptoProvider: Send + Sync {
    /// ECDSA-SHA256 sign with EC-P256 key. Returns DER-encoded signature.
    fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, HsmError>;

    /// ECDSA-SHA256 sign with EC-P256 key. Returns the raw 64-byte
    /// `r || s` signature (each 32 bytes, big-endian, zero-padded).
    /// This is what COSE_Sign1 (RFC 9053) and JWS ES256 (RFC 7515)
    /// expect; `sign` returns DER which is wrong for both.
    ///
    /// Default impl errors with NotSupported; concrete providers
    /// MUST override if they want CWT minting / JWT signing to work.
    fn sign_raw_p256(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        let _ = (key_id, data);
        Err(HsmError::NotSupported(
            "HsmCryptoProvider::sign_raw_p256".into(),
        ))
    }

    /// ECDSA-SHA256 verify with EC-P256 key. Returns true if valid.
    fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> Result<bool, HsmError>;

    /// AES-256-GCM encrypt. Returns `iv(12) || ciphertext || tag(16)`.
    fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, HsmError>;

    /// AES-256-GCM decrypt. Input is `iv(12) || ciphertext || tag(16)`.
    fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>, HsmError>;

    /// AES-CMAC generate. Returns 16-byte MAC tag.
    fn mac_generate(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, HsmError>;

    /// AES-CMAC verify. Returns true if MAC is valid.
    fn mac_verify(&self, key_id: &str, data: &[u8], mac: &[u8]) -> Result<bool, HsmError>;

    /// HKDF-SHA256 derivation. AES-256 key as IKM, context as info.
    fn derive(&self, key_id: &str, context: &[u8], len: usize) -> Result<Vec<u8>, HsmError>;

    /// OS CSPRNG random bytes.
    fn random(&self, len: usize) -> Result<Vec<u8>, HsmError>;

    /// Retrieve X.509 certificate as raw DER bytes.
    fn get_certificate_der(&self, key_id: &str) -> Result<Vec<u8>, HsmError>;

    /// Retrieve public key as SubjectPublicKeyInfo DER bytes.
    fn get_public_key_der(&self, key_id: &str) -> Result<Vec<u8>, HsmError>;

    /// Retrieve a pinned trust-anchor CA root certificate as raw DER bytes.
    ///
    /// Unlike [`get_certificate_der`](Self::get_certificate_der) — a leaf for one
    /// of the device's OWN key slots — this is a *foreign* CA root the device
    /// pins (e.g. the delegation root), provisioned via the keystore's
    /// `trust_anchors` list. `anchor_id` is e.g.
    /// [`payload::DELEGATION_ROOT_ANCHOR_ID`](crate::payload::DELEGATION_ROOT_ANCHOR_ID).
    /// Default: unsupported — a provider without a trust-anchor store declines,
    /// which simply leaves delegated-token verification off.
    fn get_trust_anchor_der(&self, _anchor_id: &str) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::NotSupported(
            "this HSM provider has no trust-anchor store".into(),
        ))
    }

    /// Get key metadata including ACL information.
    fn get_key_info(&self, key_id: &str) -> Result<KeyInfo, HsmError>;

    /// Generate a new key in the keystore.
    ///
    /// `alg` uses the VHSM_ALG_* constants as defined by the vHSM wire protocol:
    /// - `0x0002` → AES-256 (symmetric)
    /// - `0x0021` → ECC-P256 (asymmetric)
    ///
    /// Returns the public key as SubjectPublicKeyInfo DER for asymmetric
    /// algorithms, or an empty `Vec` for symmetric ones. Implementations
    /// may reject other algorithms with `NotSupported`.
    fn generate_key(&self, key_id: &str, alg: u32) -> Result<Vec<u8>, HsmError> {
        let _ = (key_id, alg);
        Err(HsmError::NotSupported("generate_key".into()))
    }

    /// Generate a PKCS#10 CSR signed by the given key. Returns DER bytes.
    /// Used for CSR-based device provisioning — device proves possession
    /// of its private key without exposing it.
    fn generate_csr(&self, key_id: &str, subject_cn: &str) -> Result<Vec<u8>, HsmError> {
        let _ = (key_id, subject_cn);
        Err(HsmError::NotSupported("CSR generation".into()))
    }

    /// AES-KW unwrap a 128-bit Content Encryption Key (CEK) using a
    /// symmetric key stored in the HSM as `key_id`. Returns the 16-byte
    /// unwrapped CEK. The KEK never leaves the HSM.
    ///
    /// Used by the SUIT decrypt path when the manifest's
    /// COSE_Encrypt recipient algorithm is `A128KW` and the device
    /// key is symmetric. See [`HsmProvider::unwrap_cek_ecdh_es`] for
    /// the more common ECDH-ES+A128KW variant.
    fn unwrap_cek_a128kw(&self, key_id: &str, wrapped_cek: &[u8]) -> Result<Vec<u8>, HsmError> {
        let _ = (key_id, wrapped_cek);
        Err(HsmError::NotSupported("unwrap_cek_a128kw".into()))
    }

    /// ECDH-ES+A128KW unwrap. The HSM performs ECDH with its EC private
    /// key (referenced by `key_id`) against the sender's `ephem_pub`
    /// public key, derives the wrapping key via Concat-KDF as specified
    /// by COSE (with `recipient_protected` mixed into the KDF context),
    /// and unwraps the `wrapped_cek` with AES-KW. Returns the 16-byte
    /// CEK. The EC private key never leaves the HSM.
    ///
    /// `ephem_pub` is the sender's ephemeral EC-P256 public key in
    /// uncompressed SEC1 form (65 bytes, leading 0x04).
    fn unwrap_cek_ecdh_es(
        &self,
        key_id: &str,
        ephem_pub: &[u8],
        wrapped_cek: &[u8],
        recipient_protected: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        let _ = (key_id, ephem_pub, wrapped_cek, recipient_protected);
        Err(HsmError::NotSupported("unwrap_cek_ecdh_es".into()))
    }
}
