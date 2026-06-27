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
/// - the guest reaches the HSM via `VhsmProvider` (vhsm-provider crate),
///   which forwards the crypto contract over the vHSM wire
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
/// Link-B bridge: `HsmCryptoProvider` over the out-of-process link-B service.
pub mod link_b;

// The host-side full-`HsmProvider` adapter over a link-B client. Re-exported as
// `hsm::LinkBProvider` (the client itself stays `hsm::link_b::LinkBClient`).
pub use link_b::LinkBProvider;

#[cfg(feature = "suit")]
pub use key_unwrap::HsmKeyUnwrap;
pub use types::*;

// The crypto contract (the handle-addressed trait + the shared types) lives in
// the `hsm-contract` crate; re-export so existing `hsm::HsmCryptoProvider` /
// `hsm::HsmError` / `hsm::KeyInfo` / `hsm::KeyType` / `hsm::KeyHandle` paths
// keep resolving.
pub use hsm_contract::{HsmCryptoProvider, HsmError, KeyHandle, KeyInfo, KeyType};
// Re-export the wire/slot-registry crate so consumers can map key_id ↔ handle
// (e.g. component-mgr's CSR endpoint) without taking a separate dependency.
pub use vhsm_proto;

// SPKI DER → COSE_Key trust-anchor converter (RustCrypto-backed); lets the
// gateway derive the manifest trust anchor from `get_public_key_der` on either
// the host (SimHsm) or the guest (VhsmProvider).
#[cfg(feature = "crypto")]
pub use crypto::cose_key_es256_from_spki_der;

/// HSM management provider.
///
/// Implementors manage the HSM keystore: provisioning and the
/// keystore/enrolment queries built on it. The crypto wire protocol
/// (sign / verify / unwrap / … on the private `vbr-vhsm` bridge) is the
/// separate [`HsmCryptoProvider`] trait, served by the underlying HSM
/// service — this trait carries NO crypto or service-lifecycle ops.
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
/// Provisioning writes key material to the real secure storage via the
/// QNX resource manager.
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

    /// Retrieve a public key by role, as COSE_Key CBOR bytes.
    fn get_public_key(&self, role: KeyRole) -> Result<Vec<u8>, HsmError>;

    // get_private_key intentionally removed — private keys never leave
    // the HSM.  Crypto (sign / verify / unwrap_cek_* / CSR-gen) lives on
    // the separate `HsmCryptoProvider` trait, keyed by handle; the key
    // stays in-HSM.  If you reach for "give me the bytes" you're
    // designing against the HSE model.

    /// Get the current provisioning lifecycle state.
    fn provisioning_state(&self) -> Result<ProvisioningState, HsmError>;

    /// Arm an in-band ENROLL_ASSISTED for `vm_id`. Used by component-mgr at
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
}

// `HsmCryptoProvider` (the handle-addressed crypto trait) now lives in the
// shared `hsm-contract` crate and is re-exported above. SimHsm implements it
// in `crypto.rs`.
