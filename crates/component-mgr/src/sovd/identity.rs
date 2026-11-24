//! The ECU's self-sovereign identity — a stable thumbprint of its HSM device
//! key, used as the token `aud` (the cross-ECU replay guard). See
//! `docs/design/authorization.md` §6 "ECU & vehicle identity".
//!
//! The id is read locally from the HSM and is immutable until an HSM reset: the
//! `device-decrypt` key is generated in-silicon on first boot and never
//! exported. A richer cert-based identity (a signed device cert in its own HSM
//! slot, for mTLS to a backend) is a planned follow-up; this thumbprint is the
//! minimal immutable id the auth layer needs today. It is *not* the Tower
//! roster name nor the CSR CN — those are mutable labels, not the crypto id.
//!
//! A host whose platform has a device id of its own, one that outlives the device
//! key, injects it instead ([`EcuId::Injected`]); [`EcuId`] states the contract
//! such an id must meet.

use std::fmt;

use hsm::KeyRole;
use sha2::{Digest, Sha256};

/// The ECU id: lowercase-hex SHA-256 of the device key's SPKI DER (what
/// `HsmCryptoProvider::get_public_key_der` returns). Stable + per-ECU.
pub fn ecu_id_from_spki_der(device_key_spki_der: &[u8]) -> String {
    hex::encode(Sha256::digest(device_key_spki_der))
}

/// Read this device's ECU id from its HSM — the `device-decrypt` key thumbprint.
/// `get_pubkey_der` is typically `|id| hsm.get_public_key_der(id).ok()`. Returns
/// `None` if the device key isn't present (an unprovisioned / freshly-wiped rig).
pub fn ecu_id(get_pubkey_der: impl Fn(&str) -> Option<Vec<u8>>) -> Option<String> {
    get_pubkey_der(KeyRole::DeviceDecryption.key_id())
        .as_deref()
        .map(ecu_id_from_spki_der)
}

/// Where this ECU's id comes from. The id is the `aud` every accepted token
/// must carry ([`super::hsm_authorizer`]) and what the HSM component serves as
/// `x-ecu-id`. A host states it once, in `component_factory::FactoryDeps::ecu_id`,
/// and takes the authorizer's from there, so the two cannot differ.
///
/// The thumbprint changes whenever the `device-decrypt` key does: a re-mint, an
/// HSM reset, a switch to a backend with its own keystore. A host whose platform
/// already has a stable device id (a UUID derived from the silicon, say) injects
/// it instead and keeps one id through all of those.
///
/// # The contract for an injected id
///
/// - **Form:** lower-case hex digits, no separators, at least
///   [`InjectedEcuId::MIN_LEN`] of them; [`EcuId::injected`] refuses anything
///   else. Reset tooling keeps only the hex digits of the id a device serves and
///   uses them as the token audience, so an id with any other character yields a
///   token the device refuses; and node-shell's identification prefix takes its
///   first 16 characters. A UUID qualifies once its dashes are dropped.
/// - **Unique per unit:** the host's to guarantee, since no unit can check it.
///   Two units given the same id accept each other's tokens (a destructive token
///   is still bound to the one boot it was minted for).
/// - **Survives a factory reset**, by design: it names the unit, not its keys.
///   The thumbprint does not survive a reset that re-mints the device key.
///   Tooling that waits for a reset to complete watches the boot id
///   (`x-boot-id`) change, never the ECU id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcuId {
    /// The `device-decrypt` key's thumbprint ([`ecu_id`]), read from the HSM each
    /// time it is needed. Today's id, for a host with none of its own.
    Thumbprint,
    /// The id the host supplies; see the contract above.
    Injected(InjectedEcuId),
    /// The host's id exists but could not be read on this device. Nothing stands
    /// in for it, so that one device never carries two ids: the unit has no id,
    /// and the authorizer's no-id rule applies (with a recovery anchor, the
    /// factory reset with `aud: ""` and nothing else).
    Unavailable,
}

impl EcuId {
    /// An injected id, checked against the contract (see [`EcuId`]).
    pub fn injected(id: impl Into<String>) -> Result<Self, InvalidEcuId> {
        InjectedEcuId::new(id).map(EcuId::Injected)
    }

    /// The id itself: the thumbprint read through `get_pubkey_der` (as for
    /// [`ecu_id`]), the injected id, or none.
    pub fn resolve(&self, get_pubkey_der: impl Fn(&str) -> Option<Vec<u8>>) -> Option<String> {
        match self {
            EcuId::Thumbprint => ecu_id(get_pubkey_der),
            EcuId::Injected(id) => Some(id.as_str().to_string()),
            EcuId::Unavailable => None,
        }
    }
}

/// A host-supplied ECU id that meets the form of [`EcuId`]'s contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectedEcuId(String);

impl InjectedEcuId {
    /// The fewest hex digits an injected id may have.
    pub const MIN_LEN: usize = 16;

    /// Check `id`: lower-case hex digits only, at least [`Self::MIN_LEN`].
    pub fn new(id: impl Into<String>) -> Result<Self, InvalidEcuId> {
        let id = id.into();
        if let Some(c) = id.chars().find(|c| !matches!(c, '0'..='9' | 'a'..='f')) {
            return Err(InvalidEcuId::NotLowerHex(c));
        }
        if id.len() < Self::MIN_LEN {
            return Err(InvalidEcuId::TooShort(id.len()));
        }
        Ok(Self(id))
    }

    /// The id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why [`EcuId::injected`] refused an id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidEcuId {
    /// A character other than `0-9` and `a-f`.
    NotLowerHex(char),
    /// Fewer than [`InjectedEcuId::MIN_LEN`] hex digits (the count given).
    TooShort(usize),
}

impl fmt::Display for InvalidEcuId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidEcuId::NotLowerHex(c) => write!(
                f,
                "ECU id holds {c:?}: only lower-case hex digits, no separators"
            ),
            InvalidEcuId::TooShort(n) => write!(
                f,
                "ECU id has {n} hex digits, fewer than {}",
                InjectedEcuId::MIN_LEN
            ),
        }
    }
}

impl std::error::Error for InvalidEcuId {}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePublicKey;

    fn spki(scalar: u8) -> Vec<u8> {
        let mut s = [0u8; 32];
        s[31] = scalar;
        SigningKey::from_bytes(&p256::FieldBytes::from(s))
            .unwrap()
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .into_vec()
    }

    #[test]
    fn ecu_id_is_a_stable_per_ecu_thumbprint() {
        let a = spki(1);
        let id_a = ecu_id_from_spki_der(&a);
        assert_eq!(id_a.len(), 64, "hex SHA-256");
        assert_eq!(id_a, ecu_id_from_spki_der(&a), "stable for the same key");
        assert_ne!(id_a, ecu_id_from_spki_der(&spki(2)), "distinct per ECU");
    }

    #[test]
    fn ecu_id_reads_device_decrypt() {
        let dd = KeyRole::DeviceDecryption.key_id();
        let der = spki(1);
        let want = ecu_id_from_spki_der(&der);
        assert_eq!(ecu_id(|id| (id == dd).then(|| der.clone())), Some(want));
        assert_eq!(ecu_id(|_| None), None, "unprovisioned → no id");
    }

    #[test]
    fn an_injected_id_wins_over_the_thumbprint_and_unavailable_is_none() {
        let der = spki(1);
        let with_key = |_: &str| Some(der.clone());
        assert_eq!(
            EcuId::Thumbprint.resolve(with_key),
            Some(ecu_id_from_spki_der(&der))
        );
        let injected = EcuId::injected("4b334ebada044b60").unwrap();
        assert_eq!(
            injected.resolve(with_key).as_deref(),
            Some("4b334ebada044b60")
        );
        assert_eq!(
            EcuId::Unavailable.resolve(with_key),
            None,
            "no thumbprint stands in"
        );
        assert_eq!(
            EcuId::Thumbprint.resolve(|_| None),
            None,
            "no device key → no id"
        );
    }

    /// The form reset tooling can use: lower-case hex, no separators, 16 or more.
    #[test]
    fn an_injected_id_must_be_lower_case_hex_of_16_or_more() {
        assert!(EcuId::injected("0123456789abcdef").is_ok());
        assert!(EcuId::injected("8d".repeat(32)).is_ok());
        let uuid = "4b334eba-da04-4b60-8d8d-8d8d8d8d8d8d";
        assert_eq!(
            EcuId::injected(uuid),
            Err(InvalidEcuId::NotLowerHex('-')),
            "a UUID with its dashes"
        );
        assert_eq!(
            EcuId::injected(uuid.replace('-', "")).unwrap(),
            EcuId::Injected(InjectedEcuId(uuid.replace('-', "")))
        );
        assert_eq!(
            EcuId::injected("0123456789ABCDEF"),
            Err(InvalidEcuId::NotLowerHex('A'))
        );
        assert_eq!(
            EcuId::injected("0123456789abcde"),
            Err(InvalidEcuId::TooShort(15))
        );
        assert_eq!(EcuId::injected(""), Err(InvalidEcuId::TooShort(0)));
        assert_eq!(
            EcuId::injected("0123456789abcdef "),
            Err(InvalidEcuId::NotLowerHex(' '))
        );
    }

    /// Every thumbprint meets the injected form too, so one rule describes every
    /// id a device serves.
    #[test]
    fn a_thumbprint_meets_the_injected_form() {
        let id = ecu_id_from_spki_der(&spki(3));
        assert!(InjectedEcuId::new(id).is_ok());
    }
}
