//! Shared HSM crypto contract.
//!
//! The HSM is one generic interface; keys are addressed by their logical-slot
//! **handle** (the canonical wire / hardware-slot / ACL number, from the
//! [`vhsm_proto`] slot registry), not by a free-form string. The `key_id`
//! string is a *derived alias* (the SimHsm filename, log lines), never the
//! identity.
//!
//! [`HsmCryptoProvider`] is implemented host-side by `SimHsm` (and, later, the
//! NXP HSE backend) and guest-side by `VhsmProvider` (forwarding over the vHSM
//! wire) — so both sides speak the same handle-addressed interface.

pub use vhsm_proto;

/// A logical key-slot handle — the canonical slot number.
///
/// Well-known slots come from the [`vhsm_proto`] registry
/// (`KeyRole::handle()` on the host side); dynamically-generated keys are
/// allocated handles at or above [`vhsm_proto::HANDLE_DYNAMIC_BASE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyHandle(pub u32);

impl KeyHandle {
    /// Wrap a raw handle number.
    pub const fn new(handle: u32) -> Self {
        KeyHandle(handle)
    }

    /// The raw handle number.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// True if this is a runtime-allocated (dynamic-range) handle rather than
    /// a well-known slot. Dynamic keys are named deterministically by their
    /// handle in the keystore; well-known keys take their registry `key_id`.
    pub fn is_dynamic(self) -> bool {
        self.0 >= vhsm_proto::HANDLE_DYNAMIC_BASE
    }
}

impl From<u32> for KeyHandle {
    fn from(v: u32) -> Self {
        KeyHandle(v)
    }
}

impl From<KeyHandle> for u32 {
    fn from(h: KeyHandle) -> Self {
        h.0
    }
}

impl std::fmt::Display for KeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:04x}", self.0)
    }
}

/// HSM error types.
#[derive(Debug)]
pub enum HsmError {
    NotProvisioned,
    AlreadyProvisioned,
    NotRunning,
    AlreadyRunning,
    KeystoreError(String),
    ProcessError(String),
    ConfigError(String),
    EnvelopeInvalid(String),
    PayloadInvalid(String),
    DecryptionFailed(String),
    RollbackRejected { current: u64, attempted: u64 },
    NotSupported(String),
    CryptoError(String),
    KeyNotFound(String),
}

impl std::fmt::Display for HsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HsmError::NotProvisioned => write!(f, "HSM not provisioned"),
            HsmError::AlreadyProvisioned => write!(f, "HSM already provisioned"),
            HsmError::NotRunning => write!(f, "HSM service not running"),
            HsmError::AlreadyRunning => write!(f, "HSM service already running"),
            HsmError::KeystoreError(s) => write!(f, "keystore error: {s}"),
            HsmError::ProcessError(s) => write!(f, "process error: {s}"),
            HsmError::ConfigError(s) => write!(f, "config error: {s}"),
            HsmError::EnvelopeInvalid(s) => write!(f, "invalid SUIT envelope: {s}"),
            HsmError::PayloadInvalid(s) => write!(f, "invalid key material payload: {s}"),
            HsmError::DecryptionFailed(s) => write!(f, "decryption failed: {s}"),
            HsmError::RollbackRejected { current, attempted } => {
                write!(
                    f,
                    "rollback rejected: security_version {attempted} <= current {current}"
                )
            }
            HsmError::NotSupported(s) => write!(f, "not supported: {s}"),
            HsmError::CryptoError(s) => write!(f, "crypto error: {s}"),
            HsmError::KeyNotFound(s) => write!(f, "key not found: {s}"),
        }
    }
}

impl std::error::Error for HsmError {}

/// Key type supported by the HSM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    EcP256,
    Ed25519,
    Aes128,
    Aes256,
    HmacSha256,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::EcP256 => write!(f, "EC-P256"),
            KeyType::Ed25519 => write!(f, "Ed25519"),
            KeyType::Aes128 => write!(f, "AES-128"),
            KeyType::Aes256 => write!(f, "AES-256"),
            KeyType::HmacSha256 => write!(f, "HMAC-SHA256"),
        }
    }
}

/// What a keystore slot holds: a cryptographic key, or the non-key monotonic
/// counter.
///
/// A slot is either a KEY (of some [`KeyType`], addressed for
/// sign/verify/encrypt/…) or a rollback-proof MONOTONIC-COUNTER (e.g. the
/// time-floor — a `u64` that only ratchets upward via
/// `read_monotonic`/`raise_monotonic`, holding NO key material). Modelling both
/// under one `kind` lets the slot inventory enumerate EVERY slot uniformly,
/// exactly as the [`vhsm_proto`] slot registry names every slot (keys +
/// `ALG_MONOTONIC`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotKind {
    /// A cryptographic key slot of this type.
    Key(KeyType),
    /// A rollback-proof monotonic-counter slot (holds no key material).
    Monotonic,
}

impl std::fmt::Display for SlotKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlotKind::Key(kt) => write!(f, "{kt}"),
            SlotKind::Monotonic => write!(f, "monotonic-counter"),
        }
    }
}

/// Information about one slot in the keystore inventory (never any key material).
///
/// A slot is either a key (`kind = Key(..)`) or the monotonic counter
/// (`kind = Monotonic`); [`SlotKind`] discriminates. Everything else is common
/// slot metadata.
#[derive(Debug, Clone)]
pub struct SlotInfo {
    /// The slot handle — the canonical identity.
    pub handle: KeyHandle,
    /// The derived alias (keystore CBOR id / SimHsm filename).
    pub key_id: String,
    /// Whether this slot is a key (and of what type) or the monotonic counter.
    pub kind: SlotKind,
    pub has_certificate: bool,
    /// Guest IDs allowed to use this slot. None = all guests.
    pub allowed_guests: Option<Vec<String>>,
    /// Operations allowed on this slot. None = all ops.
    pub allowed_ops: Option<Vec<String>>,
}

/// Crypto operations — keys never leave the HSM.
///
/// Guest-facing services (vhsm-ssd) delegate all crypto here. On production
/// hardware the implementation routes to the HSM firmware — private keys never
/// leave the secure boundary. `SimHsm` reads keys from a file keystore and runs
/// the crypto in software (RustCrypto); `VhsmProvider` forwards each op over
/// the vHSM wire.
///
/// Keys are addressed by [`KeyHandle`] (the slot number); implementations map
/// the handle to their own storage (SimHsm: a keystore filename; VhsmProvider:
/// the wire handle).
pub trait HsmCryptoProvider: Send + Sync {
    /// ECDSA-SHA256 sign with EC-P256 key. Returns DER-encoded signature.
    fn sign(&self, handle: KeyHandle, data: &[u8]) -> Result<Vec<u8>, HsmError>;

    /// ECDSA-SHA256 sign with EC-P256 key. Returns the raw 64-byte
    /// `r || s` signature (each 32 bytes, big-endian, zero-padded).
    /// This is what COSE_Sign1 (RFC 9053) and JWS ES256 (RFC 7515)
    /// expect; `sign` returns DER which is wrong for both.
    ///
    /// Default impl errors with NotSupported; concrete providers
    /// MUST override if they want CWT minting / JWT signing to work.
    fn sign_raw_p256(&self, handle: KeyHandle, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        let _ = (handle, data);
        Err(HsmError::NotSupported(
            "HsmCryptoProvider::sign_raw_p256".into(),
        ))
    }

    /// ECDSA-SHA256 verify with EC-P256 key. Returns true if valid.
    fn verify(&self, handle: KeyHandle, data: &[u8], signature: &[u8]) -> Result<bool, HsmError>;

    /// AES-256-GCM encrypt. Returns `iv(12) || ciphertext || tag(16)`.
    fn encrypt(&self, handle: KeyHandle, plaintext: &[u8]) -> Result<Vec<u8>, HsmError>;

    /// AES-256-GCM decrypt. Input is `iv(12) || ciphertext || tag(16)`.
    fn decrypt(&self, handle: KeyHandle, ciphertext: &[u8]) -> Result<Vec<u8>, HsmError>;

    /// AES-CMAC generate. Returns 16-byte MAC tag.
    fn mac_generate(&self, handle: KeyHandle, data: &[u8]) -> Result<Vec<u8>, HsmError>;

    /// AES-CMAC verify. Returns true if MAC is valid.
    fn mac_verify(&self, handle: KeyHandle, data: &[u8], mac: &[u8]) -> Result<bool, HsmError>;

    /// HKDF-SHA256 derivation. Symmetric key as IKM, context as info.
    fn derive(&self, handle: KeyHandle, context: &[u8], len: usize) -> Result<Vec<u8>, HsmError>;

    /// OS CSPRNG random bytes.
    fn random(&self, len: usize) -> Result<Vec<u8>, HsmError>;

    /// Retrieve X.509 certificate as raw DER bytes.
    fn get_certificate_der(&self, handle: KeyHandle) -> Result<Vec<u8>, HsmError>;

    /// Retrieve public key as SubjectPublicKeyInfo DER bytes.
    fn get_public_key_der(&self, handle: KeyHandle) -> Result<Vec<u8>, HsmError>;

    /// Retrieve a pinned trust-anchor CA root certificate as raw DER bytes.
    ///
    /// Unlike [`get_certificate_der`](Self::get_certificate_der) — a leaf for
    /// one of the device's OWN key slots — this is a *foreign* CA root the
    /// device pins (e.g. the delegation root), provisioned via the keystore's
    /// `trust_anchors` list. Trust anchors are NOT key slots, so this is
    /// addressed by a string `anchor_id` (not a [`KeyHandle`]). Default:
    /// unsupported — a provider without a trust-anchor store declines, which
    /// simply leaves delegated-token verification off.
    fn get_trust_anchor_der(&self, _anchor_id: &str) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::NotSupported(
            "this HSM provider has no trust-anchor store".into(),
        ))
    }

    /// Get slot metadata including ACL information. Every slot has one —
    /// a key slot reports `kind = Key(..)`, the monotonic counter `kind =
    /// Monotonic`.
    fn get_slot_info(&self, handle: KeyHandle) -> Result<SlotInfo, HsmError>;

    /// Generate a new key in the keystore, bound to `handle`.
    ///
    /// `alg` uses the `vhsm_proto::ALG_*` constants:
    /// - `0x0002` → AES-256 (symmetric)
    /// - `0x0021` → ECC-P256 (asymmetric)
    ///
    /// Returns the public key as SubjectPublicKeyInfo DER for asymmetric
    /// algorithms, or an empty `Vec` for symmetric ones. Implementations
    /// may reject other algorithms with `NotSupported`.
    fn generate_key(&self, handle: KeyHandle, alg: u32) -> Result<Vec<u8>, HsmError> {
        let _ = (handle, alg);
        Err(HsmError::NotSupported("generate_key".into()))
    }

    /// Generate a PKCS#10 CSR signed by the slot's key. Returns DER bytes.
    /// Used for CSR-based device provisioning — device proves possession
    /// of its private key without exposing it.
    fn generate_csr(&self, handle: KeyHandle, subject_cn: &str) -> Result<Vec<u8>, HsmError> {
        let _ = (handle, subject_cn);
        Err(HsmError::NotSupported("CSR generation".into()))
    }

    /// AES-KW unwrap a 128-bit Content Encryption Key (CEK) using the
    /// symmetric key in slot `handle`. Returns the 16-byte unwrapped CEK; the
    /// KEK never leaves the HSM. Used by the SUIT decrypt path when the
    /// COSE_Encrypt recipient algorithm is `A128KW`.
    fn unwrap_cek_a128kw(
        &self,
        handle: KeyHandle,
        wrapped_cek: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        let _ = (handle, wrapped_cek);
        Err(HsmError::NotSupported("unwrap_cek_a128kw".into()))
    }

    /// ECDH-ES+A128KW unwrap. The HSM performs ECDH with the EC private key in
    /// slot `handle` against the sender's `ephem_pub`, derives the wrapping key
    /// via Concat-KDF (with `recipient_protected` in the KDF context), and
    /// unwraps `wrapped_cek` with AES-KW. Returns the 16-byte CEK; the EC
    /// private key never leaves the HSM. `ephem_pub` is the sender's ephemeral
    /// EC-P256 public key in uncompressed SEC1 form (65 bytes, leading 0x04).
    fn unwrap_cek_ecdh_es(
        &self,
        handle: KeyHandle,
        ephem_pub: &[u8],
        wrapped_cek: &[u8],
        recipient_protected: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        let _ = (handle, ephem_pub, wrapped_cek, recipient_protected);
        Err(HsmError::NotSupported("unwrap_cek_ecdh_es".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_handle_conversions_and_display() {
        let h = KeyHandle::from(0x0006u32);
        assert_eq!(h.get(), 0x0006);
        assert_eq!(u32::from(h), 0x0006);
        assert_eq!(KeyHandle::new(0x0006), h);
        assert_eq!(format!("{h}"), "0x0006");
        assert!(!h.is_dynamic());
        assert!(KeyHandle(vhsm_proto::HANDLE_DYNAMIC_BASE).is_dynamic());
        assert!(KeyHandle(vhsm_proto::HANDLE_DYNAMIC_BASE - 1).is_dynamic() == false);
    }

    #[test]
    fn hsm_error_display_covers_every_variant() {
        assert_eq!(
            format!("{}", HsmError::NotProvisioned),
            "HSM not provisioned"
        );
        assert_eq!(
            format!("{}", HsmError::AlreadyProvisioned),
            "HSM already provisioned"
        );
        assert_eq!(
            format!("{}", HsmError::NotRunning),
            "HSM service not running"
        );
        assert_eq!(
            format!("{}", HsmError::AlreadyRunning),
            "HSM service already running"
        );
        assert_eq!(
            format!("{}", HsmError::KeystoreError("disk full".into())),
            "keystore error: disk full"
        );
        assert_eq!(
            format!("{}", HsmError::ProcessError("exited 1".into())),
            "process error: exited 1"
        );
        assert_eq!(
            format!("{}", HsmError::ConfigError("bad toml".into())),
            "config error: bad toml"
        );
        assert_eq!(
            format!("{}", HsmError::EnvelopeInvalid("no tag".into())),
            "invalid SUIT envelope: no tag"
        );
        assert_eq!(
            format!("{}", HsmError::PayloadInvalid("bad cbor".into())),
            "invalid key material payload: bad cbor"
        );
        assert_eq!(
            format!("{}", HsmError::DecryptionFailed("tag mismatch".into())),
            "decryption failed: tag mismatch"
        );
        assert_eq!(
            format!(
                "{}",
                HsmError::RollbackRejected {
                    current: 7,
                    attempted: 3
                }
            ),
            "rollback rejected: security_version 3 <= current 7"
        );
        assert_eq!(
            format!("{}", HsmError::NotSupported("alg".into())),
            "not supported: alg"
        );
        assert_eq!(
            format!("{}", HsmError::CryptoError("sig".into())),
            "crypto error: sig"
        );
        assert_eq!(
            format!("{}", HsmError::KeyNotFound("abc".into())),
            "key not found: abc"
        );
    }

    #[test]
    fn hsm_error_is_std_error() {
        fn assert_err<E: std::error::Error>(_e: &E) {}
        assert_err(&HsmError::NotProvisioned);
    }

    #[test]
    fn keytype_display_matches_crypto_names() {
        assert_eq!(format!("{}", KeyType::EcP256), "EC-P256");
        assert_eq!(format!("{}", KeyType::Aes256), "AES-256");
    }
}
