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
}
