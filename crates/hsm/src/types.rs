// HSM key-slot roles + provisioning lifecycle types. The crypto contract types
// (`HsmError`, `KeyInfo`, `KeyType`, `KeyHandle`, `HsmCryptoProvider`) live in
// the shared `hsm-contract` crate and are re-exported from the crate root; this
// module owns the device's `KeyRole` taxonomy, which maps each role to a slot
// handle in the `vhsm_proto` registry.
use hsm_contract::{KeyHandle, KeyType};

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
    /// hsm bundle). Rotation: rare. Verifies all host-side firmware and
    /// software today — including platform-tier and vehicle-function
    /// containers.
    SoftwareAuthority,

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

    /// Verifies operator tokens that authorise a **factory-reset** — the lone
    /// `Tier::HighConsequence` capability (ECU reboot is Operational now). The
    /// device's dedicated factory-reset authority: clearing this slot in
    /// production revokes factory-reset entirely. Held by the OEM / external
    /// reset root (the well-known factory key in dev builds). vHSM wire handle
    /// `HANDLE_FACTORY_RESET_ISSUER` = 0x0009, the number unchanged by the rename.
    FactoryResetIssuer,

    // --------------------- device TLS identity ---------------------
    //
    /// EC-P256 signing key generated **inside the HSM at provisioning
    /// time, private NEVER leaves** — the node's mTLS client identity.
    /// Authenticates this node to a backend and, in-vehicle, to a peer
    /// node's vHSM (mutual TLS, replacing the source-IP allow-list). Its
    /// leaf certificate — chaining to the fleet **identity root** (a
    /// distinct CA from `key-authority`/`sw-authority`) — is delivered
    /// per-device via the SUIT keystore manifest and held as this slot's
    /// HSM cert object. Host-in-process (like `IvdSigning`): no guest
    /// vHSM wire handle.
    TlsIdentity,

    // ------------------------ at-rest storage ----------------------
    //
    /// AES-256 symmetric key generated **inside the HSM at provisioning
    /// time, key bytes NEVER leave** — the host's at-rest storage
    /// encryption key (secstore / key-metadata). The lone symmetric slot;
    /// addressable on the guest vHSM wire (handle `0x0007`) for ENCRYPT /
    /// DECRYPT only — it has no public half, so never GET_PUBKEY / VERIFY.
    Storage,
}

impl KeyRole {
    /// The canonical slot handle (the wire / hardware-slot / ACL number) for
    /// this role. The single hsm-side role→number mapping; the `key_id` alias,
    /// algorithm, and permissions all derive from the [`vhsm_proto`] slot
    /// registry keyed off this handle.
    pub fn handle(self) -> KeyHandle {
        KeyHandle(match self {
            KeyRole::KeyAuthority => vhsm_proto::HANDLE_KEY_AUTHORITY,
            KeyRole::SoftwareAuthority => vhsm_proto::HANDLE_SW_AUTHORITY,
            KeyRole::DeviceDecryption => vhsm_proto::HANDLE_DEVICE_DECRYPT,
            KeyRole::IamSigning => vhsm_proto::HANDLE_IAM_SIGNING,
            KeyRole::IvdSigning => vhsm_proto::HANDLE_IVD_SIGNING,
            KeyRole::JwtSigning => vhsm_proto::HANDLE_JWT_SIGNING,
            KeyRole::OperationalIssuer => vhsm_proto::HANDLE_OPERATIONAL_ISSUER,
            KeyRole::FactoryResetIssuer => vhsm_proto::HANDLE_FACTORY_RESET_ISSUER,
            KeyRole::TlsIdentity => vhsm_proto::HANDLE_TLS_IDENTITY,
            KeyRole::Storage => vhsm_proto::HANDLE_STORAGE,
        })
    }

    /// Stable lower-case identifier used as the slot's key_id in the keystore
    /// CBOR schema and on-disk SimHsm filenames. DERIVED from the slot registry
    /// (the handle is canonical; the name is its alias).
    pub fn key_id(self) -> &'static str {
        vhsm_proto::slot_for_handle(self.handle().0)
            .expect("every KeyRole handle is a registered sumo-core slot")
            .key_id
    }

    /// The cryptographic key type for this role. Every role is EC-P256
    /// except `Storage`, the lone AES-256 symmetric slot.
    pub fn key_type(self) -> KeyType {
        match self {
            KeyRole::Storage => KeyType::Aes256,
            _ => KeyType::EcP256,
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
            KeyRole::DeviceDecryption,
            KeyRole::IamSigning,
            KeyRole::IvdSigning,
            KeyRole::JwtSigning,
            KeyRole::OperationalIssuer,
            KeyRole::FactoryResetIssuer,
            KeyRole::TlsIdentity,
            KeyRole::Storage,
        ]
    }

    /// `true` if the private half lives inside the HSM. Such roles
    /// are generated locally during provisioning and never cross the
    /// boundary in either direction — the HSM keystore won't accept
    /// a `private_key: Some(non-empty)` for these roles, and there's
    /// no `get_private_key` to pull them back out either.
    ///
    /// The other roles (`KeyAuthority`, `SoftwareAuthority`,
    /// `OperationalIssuer`, `FactoryResetIssuer`) are trust anchors — their
    /// private halves
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
                | KeyRole::TlsIdentity
                | KeyRole::Storage,
        )
    }
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
    fn keyrole_key_id_is_unique_per_role() {
        use std::collections::HashSet;
        let roles = [
            KeyRole::KeyAuthority,
            KeyRole::SoftwareAuthority,
            KeyRole::DeviceDecryption,
            KeyRole::IamSigning,
            KeyRole::IvdSigning,
            KeyRole::JwtSigning,
            KeyRole::OperationalIssuer,
            KeyRole::FactoryResetIssuer,
            KeyRole::TlsIdentity,
            KeyRole::Storage,
        ];
        let ids: HashSet<_> = roles.iter().map(|r| r.key_id()).collect();
        assert_eq!(ids.len(), roles.len(), "key_id() must be unique per role");

        // Pin the exact strings — these are wire-format slot names
        // baked into provisioning envelopes; drift would silently break
        // every previously-provisioned device.
        assert_eq!(KeyRole::KeyAuthority.key_id(), "key-authority");
        assert_eq!(KeyRole::SoftwareAuthority.key_id(), "sw-authority");
        assert_eq!(KeyRole::DeviceDecryption.key_id(), "device-decrypt");
        assert_eq!(KeyRole::IamSigning.key_id(), "iam-signing");
        assert_eq!(KeyRole::IvdSigning.key_id(), "ivd-signing");
        assert_eq!(KeyRole::JwtSigning.key_id(), "jwt-signing");
        assert_eq!(KeyRole::OperationalIssuer.key_id(), "operational-issuer");
        assert_eq!(KeyRole::FactoryResetIssuer.key_id(), "factory-reset-issuer");
        assert_eq!(KeyRole::TlsIdentity.key_id(), "tls-identity");
        assert_eq!(KeyRole::Storage.key_id(), "storage-key");
    }

    #[test]
    fn keyrole_maps_to_registry() {
        // The handle is canonical; key_id + alg derive from the shared slot
        // registry. Every role must resolve, and its derived name + key type
        // must agree with the registry entry (catches role↔registry drift).
        for &r in KeyRole::mandatory_roles() {
            let slot = vhsm_proto::slot_for_handle(r.handle().0)
                .unwrap_or_else(|| panic!("{r:?} handle {} not in the slot registry", r.handle()));
            assert_eq!(
                slot.key_id,
                r.key_id(),
                "{r:?} key_id must match the registry"
            );
            let expected_alg = match r.key_type() {
                KeyType::EcP256 => vhsm_proto::ALG_ECC_P256,
                KeyType::Aes256 => vhsm_proto::ALG_AES_256,
                other => panic!("{r:?} has an unexpected key_type {other}"),
            };
            assert_eq!(
                slot.alg, expected_alg,
                "{r:?} key_type must match the registry alg"
            );
        }
    }

    #[test]
    fn mandatory_roles_lists_every_role() {
        // If a new KeyRole variant lands and isn't added to
        // mandatory_roles(), this test catches it — every variant
        // should be either mandatory or explicitly opted out (and
        // there are no opt-outs today).
        let mandatory = KeyRole::mandatory_roles();
        assert_eq!(mandatory.len(), 10);

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
            KeyRole::TlsIdentity,
            KeyRole::Storage,
        ];
        let trust_anchors = [
            KeyRole::KeyAuthority,
            KeyRole::SoftwareAuthority,
            KeyRole::OperationalIssuer,
            KeyRole::FactoryResetIssuer,
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
