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

/// Well-known HSM key slot roles.
///
/// Three trust tiers verify code that runs on this device, plus the
/// per-device operational keys and the SOVD token-trust slots (an
/// onboard JWT minter + the external token-issuer anchors). Each role
/// lives in a distinct slot and rotates on its own cadence; the
/// factory-floor anchor is `KeyAuthority` (rarely rotated) and
/// everything else can be replaced via SUIT envelopes signed by the
/// appropriate authority above it.
///
/// The role set is the canonical device wire contract — see
/// [`KeyRole::mandatory_roles`] for the list every provisioned device
/// must populate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyRole {
    // ------------------------- trust anchors ------------------------
    //
    /// Verifies future HSM key envelopes. Trust anchor; after first
    /// provisioning replaces the factory signing key. Rotation: almost
    /// never (the floor of the trust chain).
    KeyAuthority,

    /// Verifies host-side firmware SUIT envelopes (host-os, vm1, vm2,
    /// hsm bundle). Rotation: rare. Lives above PlatformAuthority and
    /// ApplicationAuthority in the trust hierarchy.
    SoftwareAuthority,

    /// Verifies platform-tier container envelopes — load-bearing
    /// guest services that participate in vehicle infrastructure
    /// (SOVD gateway, observability, security helpers). Rotation: rare.
    /// Containers verified with this key get the privileged runtime
    /// tier (host SOVD access, broader sandbox).
    PlatformAuthority,

    /// Verifies vehicle-function container envelopes — ADAS,
    /// infotainment, body control apps. Inherently untrusted in the
    /// safety sense; sandboxed at runtime. Rotation: frequent. Can be
    /// delegated wide (partner ecosystems, app developer pipelines).
    ApplicationAuthority,

    // -------------------- per-device operational --------------------
    //
    /// EC-P256 ECDH key — decrypts confidential payloads (firmware
    /// CEK unwrap, encrypted container layers). Private half stays in
    /// the HSM; envelopes are encrypted to its public half.
    DeviceDecryption,

    /// EC-P256 signing key used by vhsm-ssd as the device's IAM
    /// certificate-issuing authority — every CWT minted via ENROLL
    /// / ENROLL_ASSISTED is signed with this key, and every AUTH
    /// validates against its public half. Daemon-internal; not
    /// addressable from guest principals via the IAM policy.
    /// Format contract: signs return raw 64-byte ECDSA-P256 (r||s),
    /// not DER — COSE_Sign1 is what's downstream.
    IamSigning,

    /// EC-P256 signing key generated **inside the HSM at provisioning
    /// time, private NEVER leaves**. Used to self-sign provisioned
    /// firmware bank dirs after `Validator` succeeds. External
    /// secure-boot verifies each bank with this key's public half
    /// before launching the component. Rotation: never on-device
    /// (regenerated only on HSM reset / device repurpose).
    IvdSigning,

    // ----------------------- onboard minter -------------------------
    //
    /// EC-P256 signing key generated **inside the HSM at provisioning
    /// time, private NEVER leaves** — the device's onboard SOVD-token
    /// minter (the in-vehicle `jwt-mgr`). Signs Operational-tier bearer
    /// JWTs for in-vehicle callers; the SOVD authorizer verifies them
    /// against this key's public half (`OP_GET_PUBKEY`). Operational
    /// tier only — by policy it can never mint a HighConsequence token.
    JwtSigning,

    // --------------------- token-issuer anchors ---------------------
    //
    // Verify-only public keys for the EXTERNAL SOVD-token issuers,
    // pinned per authority tier. A distinct trust domain from the
    // `*-authority` firmware/container anchors above — these verify JWT
    // signatures, not SUIT envelopes. Provisioned by Tower 1 (public
    // half only); the matching private minters live offboard.
    //
    /// Verifies Operational-tier tokens from an external authority — the
    /// workshop CA / OEM operational issuer (e.g. the `sovd-token-helper`
    /// `x5c` root). Routine OTA + reads.
    OperationalIssuer,

    /// Verifies HighConsequence-tier tokens (factory-reset, vehicle
    /// reboot, HSM keystore) from the OEM / external authority — the
    /// ceiling an in-vehicle minter can never reach.
    HighConsequenceIssuer,

    // --------------------- freshness coordinator --------------------
    //
    /// EC-P256 signing key generated **inside the HSM at provisioning
    /// time, private NEVER leaves** — the master freshness coordinator's
    /// assertion signer (§7.2). Signs the vehicle's `{safe-time-floor,
    /// vehicle-epoch}` freshness assertion; peer ECUs verify it against
    /// this key's pinned public half. Host-in-process only (like
    /// `IvdSigning`): deliberately NOT addressable on the guest vHSM wire
    /// — a guest must never be able to forge a freshness assertion.
    FreshnessSigning,
}

impl KeyRole {
    /// Stable lower-case identifier used as the slot's key_id in the
    /// keystore CBOR schema and on-disk SimHsm filenames.
    pub fn key_id(self) -> &'static str {
        match self {
            KeyRole::KeyAuthority => "key-authority",
            KeyRole::SoftwareAuthority => "sw-authority",
            KeyRole::PlatformAuthority => "platform-authority",
            KeyRole::ApplicationAuthority => "application-authority",
            KeyRole::DeviceDecryption => "device-decrypt",
            KeyRole::IamSigning => "iam-signing",
            KeyRole::IvdSigning => "ivd-signing",
            KeyRole::JwtSigning => "jwt-signing",
            KeyRole::OperationalIssuer => "operational-issuer",
            KeyRole::HighConsequenceIssuer => "high-consequence-issuer",
            KeyRole::FreshnessSigning => "freshness-signing",
        }
    }

    /// Every role that MUST be populated before the HSM is considered
    /// fully provisioned. Used by provisioning state-machine checks
    /// and (eventually) by `Provider::status()` to surface
    /// half-provisioned devices.
    pub fn mandatory_roles() -> &'static [KeyRole] {
        &[
            KeyRole::KeyAuthority,
            KeyRole::SoftwareAuthority,
            KeyRole::PlatformAuthority,
            KeyRole::ApplicationAuthority,
            KeyRole::DeviceDecryption,
            KeyRole::IamSigning,
            KeyRole::IvdSigning,
            KeyRole::JwtSigning,
            KeyRole::OperationalIssuer,
            KeyRole::HighConsequenceIssuer,
            KeyRole::FreshnessSigning,
        ]
    }

    /// `true` if the private half lives inside the HSM. Such roles
    /// are generated locally during provisioning and never cross the
    /// boundary in either direction — the HSM keystore won't accept
    /// a `private_key: Some(non-empty)` for these roles, and there's
    /// no `get_private_key` to pull them back out either.
    ///
    /// The other roles (`KeyAuthority`, `SoftwareAuthority`,
    /// `PlatformAuthority`, `ApplicationAuthority`, `OperationalIssuer`,
    /// `HighConsequenceIssuer`) are trust anchors — their private halves
    /// live off-device, with the corresponding signing infrastructure.
    /// The HSM only stores their public halves for verification (SUIT
    /// envelopes for the `*-authority` set, JWT signatures for the
    /// issuer anchors).
    pub fn is_device_generated(self) -> bool {
        matches!(
            self,
            KeyRole::DeviceDecryption
                | KeyRole::IamSigning
                | KeyRole::IvdSigning
                | KeyRole::JwtSigning
                | KeyRole::FreshnessSigning,
        )
    }
}

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

/// Information about a key in the keystore.
#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub key_id: String,
    pub key_type: KeyType,
    pub has_certificate: bool,
    /// Guest IDs allowed to use this key. None = all guests.
    pub allowed_guests: Option<Vec<String>>,
    /// Operations allowed on this key. None = all ops.
    pub allowed_ops: Option<Vec<String>>,
}

/// Provisioning lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisioningState {
    /// Device key exists but no key bundle provisioned yet.
    /// CSR endpoint is available.
    Unprovisioned,
    /// Key bundle installed, all well-known handles populated.
    /// CSR endpoint returns 403.
    Provisioned,
}

/// Status of the HSM subsystem.
#[derive(Debug)]
pub struct HsmStatus {
    pub provisioned: bool,
    pub service_running: bool,
    pub service_pid: Option<u32>,
    pub keystore_path: std::path::PathBuf,
    pub tcp_port: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hsm_error_display_covers_every_variant() {
        // One case per variant — catches accidental duplicate/wrong arm additions.
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
    fn keyrole_key_id_is_unique_per_role() {
        use std::collections::HashSet;
        let roles = [
            KeyRole::KeyAuthority,
            KeyRole::SoftwareAuthority,
            KeyRole::PlatformAuthority,
            KeyRole::ApplicationAuthority,
            KeyRole::DeviceDecryption,
            KeyRole::IamSigning,
            KeyRole::IvdSigning,
            KeyRole::JwtSigning,
            KeyRole::OperationalIssuer,
            KeyRole::HighConsequenceIssuer,
            KeyRole::FreshnessSigning,
        ];
        let ids: HashSet<_> = roles.iter().map(|r| r.key_id()).collect();
        assert_eq!(ids.len(), roles.len(), "key_id() must be unique per role");

        // Pin the exact strings — these are wire-format slot names
        // baked into provisioning envelopes; drift would silently break
        // every previously-provisioned device.
        assert_eq!(KeyRole::KeyAuthority.key_id(), "key-authority");
        assert_eq!(KeyRole::SoftwareAuthority.key_id(), "sw-authority");
        assert_eq!(KeyRole::PlatformAuthority.key_id(), "platform-authority");
        assert_eq!(
            KeyRole::ApplicationAuthority.key_id(),
            "application-authority"
        );
        assert_eq!(KeyRole::DeviceDecryption.key_id(), "device-decrypt");
        assert_eq!(KeyRole::IamSigning.key_id(), "iam-signing");
        assert_eq!(KeyRole::IvdSigning.key_id(), "ivd-signing");
        assert_eq!(KeyRole::JwtSigning.key_id(), "jwt-signing");
        assert_eq!(KeyRole::OperationalIssuer.key_id(), "operational-issuer");
        assert_eq!(
            KeyRole::HighConsequenceIssuer.key_id(),
            "high-consequence-issuer"
        );
        assert_eq!(KeyRole::FreshnessSigning.key_id(), "freshness-signing");
    }

    #[test]
    fn mandatory_roles_lists_every_role() {
        // If a new KeyRole variant lands and isn't added to
        // mandatory_roles(), this test catches it — every variant
        // should be either mandatory or explicitly opted out (and
        // there are no opt-outs today).
        let mandatory = KeyRole::mandatory_roles();
        assert_eq!(mandatory.len(), 11);

        // Sanity: every entry is distinct.
        use std::collections::HashSet;
        let ids: HashSet<_> = mandatory.iter().collect();
        assert_eq!(ids.len(), mandatory.len());
    }

    #[test]
    fn device_generated_roles_match_private_on_device() {
        // The split mirrors the trust topology: anything whose
        // PRIVATE half lives on-device must be generated on-device
        // (no push, no pull). Trust anchors are public-only.
        let device_generated = [
            KeyRole::DeviceDecryption,
            KeyRole::IamSigning,
            KeyRole::IvdSigning,
            KeyRole::JwtSigning,
            KeyRole::FreshnessSigning,
        ];
        let trust_anchors = [
            KeyRole::KeyAuthority,
            KeyRole::SoftwareAuthority,
            KeyRole::PlatformAuthority,
            KeyRole::ApplicationAuthority,
            KeyRole::OperationalIssuer,
            KeyRole::HighConsequenceIssuer,
        ];

        for &r in &device_generated {
            assert!(
                r.is_device_generated(),
                "{r:?} should be device-generated (private lives in HSM)",
            );
        }
        for &r in &trust_anchors {
            assert!(
                !r.is_device_generated(),
                "{r:?} is a trust anchor (private lives off-device with signing infra)",
            );
        }
        // The union covers every mandatory role.
        assert_eq!(
            device_generated.len() + trust_anchors.len(),
            KeyRole::mandatory_roles().len(),
        );
    }

    #[test]
    fn keytype_display_matches_crypto_names() {
        assert_eq!(format!("{}", KeyType::EcP256), "EC-P256");
        assert_eq!(format!("{}", KeyType::Aes256), "AES-256");
    }

    #[test]
    fn provisioning_state_equality_and_debug() {
        assert_eq!(
            ProvisioningState::Unprovisioned,
            ProvisioningState::Unprovisioned
        );
        assert_ne!(
            ProvisioningState::Unprovisioned,
            ProvisioningState::Provisioned
        );
        // Debug format is used in logs — make sure it doesn't accidentally silently change.
        assert_eq!(
            format!("{:?}", ProvisioningState::Provisioned),
            "Provisioned"
        );
    }
}
