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
//! key, injects it instead ([`EcuId::Injected`]); the thumbprint is the default.

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

/// Where this ECU's id comes from: the `aud` every accepted token must carry
/// ([`super::hsm_authorizer`]) and the HSM component's device id.
///
/// The thumbprint changes whenever the `device-decrypt` key does: a re-mint, an
/// HSM reset, a switch to a backend with its own keystore. A host whose platform
/// already has a stable device id (a UUID derived from the silicon, say) injects
/// it instead, and then holds one id across all of those.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum EcuId {
    /// The `device-decrypt` key's thumbprint ([`ecu_id`]), read from the HSM each
    /// time it is needed. The default, for a host with no id of its own.
    #[default]
    Thumbprint,
    /// The id the host supplies.
    Injected(String),
    /// The host's id exists but could not be read on this device. Nothing stands
    /// in for it, so that one device never carries two ids: the authorizer trusts
    /// no issuer and the component reports no id.
    Unavailable,
}

impl EcuId {
    /// The id itself: the thumbprint read through `get_pubkey_der` (as for
    /// [`ecu_id`]), the injected id, or none. An empty id counts as none, since an
    /// empty `aud` would be the same on every ECU.
    pub fn resolve(&self, get_pubkey_der: impl Fn(&str) -> Option<Vec<u8>>) -> Option<String> {
        match self {
            EcuId::Thumbprint => ecu_id(get_pubkey_der),
            EcuId::Injected(id) => Some(id.clone()),
            EcuId::Unavailable => None,
        }
        .filter(|id| !id.is_empty())
    }
}

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
        assert_eq!(
            EcuId::Injected("4b334eba".into()).resolve(with_key),
            Some("4b334eba".to_string())
        );
        assert_eq!(
            EcuId::Unavailable.resolve(with_key),
            None,
            "no thumbprint stands in"
        );
        assert_eq!(EcuId::default(), EcuId::Thumbprint);
    }

    /// An empty id is no id: the old `unwrap_or_default()` turned a missing
    /// device key into `aud = ""`, which every ECU would accept alike.
    #[test]
    fn an_empty_or_missing_id_resolves_to_none() {
        assert_eq!(EcuId::Injected(String::new()).resolve(|_| None), None);
        assert_eq!(EcuId::Thumbprint.resolve(|_| None), None);
    }
}
