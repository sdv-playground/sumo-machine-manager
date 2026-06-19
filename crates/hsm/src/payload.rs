//! HSM key material payload — CBOR schema for SUIT envelope contents.
//!
//! Defines the binary format carried inside a SUIT envelope with
//! component ID `["hsm", "keys"]`. The same schema is consumed by
//! every backend (SimHsm in dev/test; HSE-backed providers in
//! production).
//!
//! # Schema v3 — no private keys; public leaf certs welcome
//!
//! The keystore enumerates the slots a provisioned HSM should expose
//! and the trust anchors (public halves) used to verify subsequent
//! envelopes. **Private key material never crosses this boundary.**
//! Slots whose private half lives on-device (device-decrypt, ecu-
//! signing, ivd-signing, jwt-signing, application keys, ...) are
//! enumerated with `anchor_public_key = None`; the HSM generates the
//! keypair locally during provisioning and exposes the public half
//! through `HsmCryptoProvider::get_public_key_der` afterwards.
//!
//! v2 dropped v1's `private_key` field (never ship privates) and the
//! per-key `certificate` field. v3 re-introduces leaf certificates, but
//! ONLY as **signed leaves for device-generated identity keys** (e.g.
//! the `tls-identity` mTLS leaf), carried in the top-level
//! `certificates` list. A leaf is a public artifact, **inert without the
//! HSM-held private key**, so carrying it in the already-signed +
//! device-encrypted envelope adds no secret and no new trust
//! assumption — it just lands the cert atomically with the key it
//! certifies, on the one keystore channel. Private keys still never
//! cross. Decoders reject v1/v2 envelopes outright.
//!
//! # Wire format (CBOR, integer keys)
//!
//! ```text
//! HsmKeystore = {
//!   0: uint,            ; schema_version (must be 4)
//!   1: uint,            ; security_version (anti-rollback floor)
//!   2: [* Identity],
//!   3: [* KeySlot],
//!   4: [* LeafCert],        ; optional; signed leaves for device keys
//!   5: [* TrustAnchorCert], ; optional; foreign CA roots the device pins
//! }
//!
//! Identity = {
//!   0: tstr,            ; identity_id
//!   1: bstr,            ; EC-P256 uncompressed public (65 bytes)
//! }
//!
//! KeySlot = {
//!   0: tstr,            ; key_id
//!   1: uint,            ; key_kind: 0 = EC-P256, 1 = AES-256
//!   2: ?bstr,           ; anchor_public_key — Some only for trust
//!                       ;   anchors (EC-P256 only); None means
//!                       ;   "device generates this locally."
//!   3: ?[* tstr],       ; allowed_guests (None = unrestricted)
//!   4: ?[* uint],       ; allowed_ops (None = all)
//! }
//!
//! LeafCert = {
//!   0: tstr,            ; key_id — must name an EC-P256 slot above
//!   1: bstr,            ; certificate — DER X.509 leaf
//! }
//!
//! TrustAnchorCert = {
//!   0: tstr,            ; anchor_id (e.g. "delegation-root")
//!   1: bstr,            ; certificate — DER X.509 CA root
//! }
//! ```

use serde::{Deserialize, Serialize};

use crate::KeyType;

/// Schema version. v4 adds an optional top-level `trust_anchors` list
/// (foreign CA roots the device pins, e.g. the delegation root) on top of
/// v3's `certificates` (signed leaves for device-generated identity keys).
/// All public, never a private byte. v1/v2/v3 envelopes are rejected.
pub const SCHEMA_VERSION: u64 = 4;

/// Well-known factory signing key — verifies the very first HSM key
/// provisioning envelope.
///
/// This is NOT real security. The private key is published in the
/// spec (`scalar = 1`, generator point as public). After first
/// provisioning the Key Authority replaces it as trust anchor.
pub const FACTORY_SIGNING_SCALAR: [u8; 32] = {
    let mut s = [0u8; 32];
    s[31] = 1;
    s
};

/// Factory signing key public half (P-256 generator point G,
/// uncompressed, leading `0x04`).
#[rustfmt::skip]
pub const FACTORY_SIGNING_PUBLIC: [u8; 65] = [
    0x04,
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
    0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
    0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
    0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
    0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5,
];

/// Top-level keystore payload inside the SUIT envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmKeystore {
    #[serde(rename = "0")]
    pub schema_version: u64,

    /// Security version — must exceed current value on re-provision
    /// (anti-rollback floor).
    #[serde(rename = "1")]
    pub security_version: u64,

    /// Guest identities for challenge-response registration.
    #[serde(rename = "2")]
    pub identities: Vec<IdentityDef>,

    /// Key slots — enumerated, not key material.
    #[serde(rename = "3")]
    pub slots: Vec<KeySlot>,

    /// Signed leaf certificates for device-generated identity keys
    /// (v3). Empty on first provision; populated on re-provision once a
    /// CA has issued the leaf from the device's CSR (e.g. the
    /// `tls-identity` mTLS leaf). Each entry names a slot above.
    #[serde(rename = "4", default, skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<LeafCert>,

    /// Foreign CA root certificates the device pins (v4). Each is a trust
    /// anchor a delegated token's `x5c` chain must validate to — e.g. the
    /// `delegation-root` (the CA that signs workshop reset-grant leaves).
    /// Distinct from `certificates`: those certify the device's OWN keys; a
    /// trust anchor certifies no slot here. Empty when the device pins no
    /// external roots.
    #[serde(rename = "5", default, skip_serializing_if = "Vec::is_empty")]
    pub trust_anchors: Vec<TrustAnchorCert>,
}

/// A signed leaf certificate for one of the keystore's device-generated
/// identity keys. Public + inert without the HSM-held private key — see
/// the schema-v3 note. The device writes it to `{key_id}.cert`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeafCert {
    /// The slot this leaf certifies — must name an EC-P256 `KeySlot`.
    #[serde(rename = "0")]
    pub key_id: String,

    /// DER-encoded X.509 leaf certificate.
    #[serde(rename = "1", with = "serde_bytes")]
    pub certificate: Vec<u8>,
}

/// Well-known [`TrustAnchorCert::anchor_id`] for the delegation root — the CA
/// whose chain a delegated operator token (`x5c`) must validate to. Shared by
/// the minter (which embeds it) and the device authorizer (which pins it).
pub const DELEGATION_ROOT_ANCHOR_ID: &str = "delegation-root";

/// A foreign CA root certificate the device pins as a trust anchor (v4). The
/// root a delegated token's `x5c` chain validates to — NOT a cert for any slot
/// in this keystore. Public trust material; the device writes it to
/// `roots/{anchor_id}.cert`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAnchorCert {
    /// Stable id for this anchor, e.g. [`DELEGATION_ROOT_ANCHOR_ID`].
    #[serde(rename = "0")]
    pub anchor_id: String,

    /// DER-encoded X.509 CA root certificate.
    #[serde(rename = "1", with = "serde_bytes")]
    pub certificate: Vec<u8>,
}

/// Guest identity for challenge-response registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityDef {
    #[serde(rename = "0")]
    pub identity_id: String,

    /// EC-P256 public key (65 bytes uncompressed, leading `0x04`).
    #[serde(rename = "1", with = "serde_bytes")]
    pub public_key: Vec<u8>,
}

/// A single key slot. Two shapes:
///
/// - **Trust anchor**: `anchor_public_key = Some(pub_bytes)`. EC-P256
///   only. HSM stores the public half for envelope verification; the
///   private half lives off-device with the signing infrastructure.
///
/// - **Device-generated**: `anchor_public_key = None`. HSM generates
///   the keypair (EC-P256) or symmetric key (AES-256) locally during
///   provisioning. The private/key bytes never cross the envelope
///   boundary in either direction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySlot {
    #[serde(rename = "0")]
    pub key_id: String,

    /// `KEY_TYPE_EC_P256` (0) or `KEY_TYPE_AES_256` (1).
    #[serde(rename = "1")]
    pub key_kind: u64,

    /// `Some(uncompressed_sec1_bytes)` for trust anchors, `None` for
    /// device-generated slots. AES slots are always device-generated
    /// and so always have `None` here.
    #[serde(
        rename = "2",
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes_opt"
    )]
    pub anchor_public_key: Option<Vec<u8>>,

    /// Guest identities allowed to use this key. `None` = unrestricted.
    #[serde(rename = "3", default, skip_serializing_if = "Option::is_none")]
    pub allowed_guests: Option<Vec<String>>,

    /// Permitted operation codes (see `OP_*` constants below). `None`
    /// = unrestricted (effectively allows what the key type supports).
    #[serde(rename = "4", default, skip_serializing_if = "Option::is_none")]
    pub allowed_ops: Option<Vec<u64>>,
}

/// Key kinds. Single u64 on the wire to keep CBOR compact.
pub const KEY_TYPE_EC_P256: u64 = 0;
pub const KEY_TYPE_AES_256: u64 = 1;
pub const KEY_TYPE_ED25519: u64 = 2;
pub const KEY_TYPE_AES_128: u64 = 3;
pub const KEY_TYPE_HMAC_SHA256: u64 = 4;

/// Operation codes for the `allowed_ops` field. These name the
/// runtime vHSM wire operations a slot may serve once provisioned;
/// they do NOT describe what the envelope contains.
///
/// `OP_GET_CERT` gates the runtime cert query. The cert it returns is
/// the slot's leaf — delivered in the v3 top-level `certificates` list
/// (for the device's own identity keys, e.g. `tls-identity`) or written
/// post-provisioning by a CSR-issuance flow; either way the slot policy
/// must permit the op.
pub const OP_SIGN: u64 = 0;
pub const OP_VERIFY: u64 = 1;
pub const OP_ENCRYPT: u64 = 2;
pub const OP_DECRYPT: u64 = 3;
pub const OP_DERIVE: u64 = 4;
pub const OP_GET_CERT: u64 = 5;
pub const OP_GET_PUBKEY: u64 = 6;

impl KeySlot {
    /// Convenience: this slot is a trust anchor (envelope ships the
    /// public half; HSM never sees a private byte for it).
    pub fn is_anchor(&self) -> bool {
        self.anchor_public_key.is_some()
    }

    /// Convenience: this slot is device-generated (HSM generates the
    /// keypair locally; no envelope-side material).
    pub fn is_device_generated(&self) -> bool {
        self.anchor_public_key.is_none()
    }

    /// Convert the wire-format kind to the typed `KeyType` enum.
    pub fn parsed_key_type(&self) -> Option<KeyType> {
        match self.key_kind {
            KEY_TYPE_EC_P256 => Some(KeyType::EcP256),
            KEY_TYPE_AES_256 => Some(KeyType::Aes256),
            KEY_TYPE_ED25519 => Some(KeyType::Ed25519),
            KEY_TYPE_AES_128 => Some(KeyType::Aes128),
            KEY_TYPE_HMAC_SHA256 => Some(KeyType::HmacSha256),
            _ => None,
        }
    }

    /// Convert `allowed_ops` codes to vhsm-ssd op name strings.
    pub fn ops_as_strings(&self) -> Option<Vec<&'static str>> {
        self.allowed_ops.as_ref().map(|ops| {
            ops.iter()
                .filter_map(|op| match *op {
                    OP_SIGN => Some("SIGN"),
                    OP_VERIFY => Some("VERIFY"),
                    OP_ENCRYPT => Some("ENCRYPT"),
                    OP_DECRYPT => Some("DECRYPT"),
                    OP_DERIVE => Some("DERIVE"),
                    OP_GET_CERT => Some("GET_CERT"),
                    OP_GET_PUBKEY => Some("GET_PUBKEY"),
                    _ => None,
                })
                .collect()
        })
    }

    /// Sanity-check the slot shape: AES must be device-generated; EC
    /// trust anchors must carry a 65-byte uncompressed key. Called
    /// during decode.
    fn validate(&self) -> Result<(), String> {
        match (self.key_kind, &self.anchor_public_key) {
            (KEY_TYPE_AES_256, Some(_)) => Err(format!(
                "slot '{}': AES keys are device-generated; \
                 cannot ship an anchor_public_key",
                self.key_id
            )),
            (KEY_TYPE_EC_P256, Some(pk)) if pk.len() != 65 || pk[0] != 0x04 => Err(format!(
                "slot '{}': EC anchor public must be uncompressed SEC1 \
                 (65 bytes leading 0x04), got {} bytes",
                self.key_id,
                pk.len(),
            )),
            _ => Ok(()),
        }
    }
}

/// Serialize an `HsmKeystore` to CBOR bytes.
pub fn encode(keystore: &HsmKeystore) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(keystore, &mut buf).map_err(|e| format!("CBOR encode: {e}"))?;
    Ok(buf)
}

/// Deserialize an `HsmKeystore` from CBOR bytes. Rejects any
/// `schema_version != SCHEMA_VERSION` (v1 envelopes are dead) and
/// runs `KeySlot::validate` on each slot.
pub fn decode(data: &[u8]) -> Result<HsmKeystore, String> {
    let ks: HsmKeystore = ciborium::from_reader(data).map_err(|e| format!("CBOR decode: {e}"))?;
    if ks.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "unsupported schema version {} (this build only accepts {SCHEMA_VERSION}; \
             v1/v2/v3 envelopes are not decoded)",
            ks.schema_version
        ));
    }
    for slot in &ks.slots {
        slot.validate()?;
    }
    // A leaf cert must certify an EC-P256 slot present in this keystore
    // (you can't have an X.509 cert for an AES key, nor for a key the
    // device won't provision).
    for c in &ks.certificates {
        match ks.slots.iter().find(|s| s.key_id == c.key_id) {
            Some(s) if s.key_kind == KEY_TYPE_EC_P256 => {}
            Some(s) => {
                return Err(format!(
                    "leaf cert for '{}' requires an EC-P256 slot (got kind {})",
                    c.key_id, s.key_kind
                ))
            }
            None => return Err(format!("leaf cert references unknown slot '{}'", c.key_id)),
        }
    }
    // A trust anchor must look like a DER X.509 cert (SEQUENCE). It certifies no
    // slot here — it's a foreign CA root the device pins — so there's nothing to
    // cross-check against `slots`, just basic well-formedness.
    for a in &ks.trust_anchors {
        if a.certificate.first() != Some(&0x30) {
            return Err(format!(
                "trust anchor '{}': certificate is not DER X.509 (expected SEQUENCE 0x30)",
                a.anchor_id
            ));
        }
    }
    Ok(ks)
}

/// Serde helper for `Option<Vec<u8>>` as CBOR bstr.
mod serde_bytes_opt {
    use serde::{self, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serde_bytes::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::Deserialize;
        let opt: Option<serde_bytes::ByteBuf> = Option::deserialize(deserializer)?;
        Ok(opt.map(|b| b.into_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor(id: &str, pubkey_byte: u8) -> KeySlot {
        let mut pk = vec![0x04];
        pk.extend_from_slice(&[pubkey_byte; 32]);
        pk.extend_from_slice(&[pubkey_byte.wrapping_add(1); 32]);
        KeySlot {
            key_id: id.to_string(),
            key_kind: KEY_TYPE_EC_P256,
            anchor_public_key: Some(pk),
            allowed_guests: None,
            allowed_ops: Some(vec![OP_VERIFY]),
        }
    }

    fn device_generated_ec(id: &str, guest: &str) -> KeySlot {
        KeySlot {
            key_id: id.to_string(),
            key_kind: KEY_TYPE_EC_P256,
            anchor_public_key: None,
            allowed_guests: Some(vec![guest.to_string()]),
            allowed_ops: Some(vec![OP_SIGN, OP_VERIFY, OP_GET_PUBKEY]),
        }
    }

    fn device_generated_aes(id: &str, guest: &str) -> KeySlot {
        KeySlot {
            key_id: id.to_string(),
            key_kind: KEY_TYPE_AES_256,
            anchor_public_key: None,
            allowed_guests: Some(vec![guest.to_string()]),
            allowed_ops: Some(vec![OP_ENCRYPT, OP_DECRYPT]),
        }
    }

    fn sample_keystore() -> HsmKeystore {
        HsmKeystore {
            schema_version: SCHEMA_VERSION,
            security_version: 1,
            identities: vec![IdentityDef {
                identity_id: "bali-vm-1".into(),
                public_key: {
                    let mut pk = vec![0x04];
                    pk.extend_from_slice(&[0x11; 32]);
                    pk.extend_from_slice(&[0x22; 32]);
                    pk
                },
            }],
            slots: vec![
                anchor("key-authority", 0xAA),
                anchor("sw-authority", 0xBB),
                anchor("platform-authority", 0xCC),
                anchor("application-authority", 0xDD),
                device_generated_ec("device-decrypt", "bali-vm-1"),
                device_generated_ec("iam-signing", "bali-vm-1"),
                device_generated_ec("ivd-signing", "bali-vm-1"),
                device_generated_aes("storage-key", "bali-vm-1"),
            ],
            certificates: Vec::new(),
            trust_anchors: Vec::new(),
        }
    }

    #[test]
    fn roundtrip_mandatory_slots() {
        let ks = sample_keystore();
        let bytes = encode(&ks).unwrap();
        let back = decode(&bytes).unwrap();
        assert_eq!(back.schema_version, SCHEMA_VERSION);
        assert_eq!(back.slots.len(), ks.slots.len());
        assert!(back.slots[0].is_anchor());
        assert!(back.slots[4].is_device_generated());
    }

    #[test]
    fn decode_rejects_old_versions() {
        for v in [1u64, 2, 3] {
            let mut ks = sample_keystore();
            ks.schema_version = v;
            let bytes = encode(&ks).unwrap();
            let err = decode(&bytes).unwrap_err();
            assert!(err.contains(&format!("unsupported schema version {v}")));
            assert!(err.contains("not decoded"));
        }
    }

    #[test]
    fn roundtrip_preserves_leaf_certificate() {
        let mut ks = sample_keystore();
        // A (stand-in) DER leaf for a device-generated EC slot.
        let leaf = vec![0x30, 0x82, 0x01, 0x23, 0xAB, 0xCD];
        ks.certificates.push(LeafCert {
            key_id: "iam-signing".into(),
            certificate: leaf.clone(),
        });
        let bytes = encode(&ks).unwrap();
        let back = decode(&bytes).unwrap();
        assert_eq!(back.certificates.len(), 1);
        assert_eq!(back.certificates[0].key_id, "iam-signing");
        assert_eq!(back.certificates[0].certificate, leaf);
    }

    #[test]
    fn roundtrip_preserves_trust_anchor() {
        let mut ks = sample_keystore();
        // A (stand-in) DER CA root — leading SEQUENCE tag.
        let root = vec![0x30, 0x82, 0x02, 0x00, 0xCA, 0xFE];
        ks.trust_anchors.push(TrustAnchorCert {
            anchor_id: DELEGATION_ROOT_ANCHOR_ID.into(),
            certificate: root.clone(),
        });
        let back = decode(&encode(&ks).unwrap()).unwrap();
        assert_eq!(back.trust_anchors.len(), 1);
        assert_eq!(back.trust_anchors[0].anchor_id, DELEGATION_ROOT_ANCHOR_ID);
        assert_eq!(back.trust_anchors[0].certificate, root);
    }

    #[test]
    fn empty_trust_anchors_is_wire_compatible_omitted() {
        // A keystore pinning no external roots must not emit the field.
        let ks = sample_keystore();
        assert!(ks.trust_anchors.is_empty());
        assert!(decode(&encode(&ks).unwrap())
            .unwrap()
            .trust_anchors
            .is_empty());
    }

    #[test]
    fn decode_rejects_non_der_trust_anchor() {
        let mut ks = sample_keystore();
        ks.trust_anchors.push(TrustAnchorCert {
            anchor_id: "delegation-root".into(),
            certificate: vec![0x99, 0x00], // not a DER SEQUENCE
        });
        let err = decode(&encode(&ks).unwrap()).unwrap_err();
        assert!(err.contains("delegation-root"));
        assert!(err.contains("not DER X.509"));
    }

    #[test]
    fn empty_certificates_is_wire_compatible_omitted() {
        // First-provision keystore (no certs) must not emit the field.
        let ks = sample_keystore();
        assert!(ks.certificates.is_empty());
        let bytes = encode(&ks).unwrap();
        // Round-trips back to an empty list (default on absence).
        assert!(decode(&bytes).unwrap().certificates.is_empty());
    }

    #[test]
    fn decode_rejects_leaf_cert_for_unknown_slot() {
        let mut ks = sample_keystore();
        ks.certificates.push(LeafCert {
            key_id: "no-such-slot".into(),
            certificate: vec![0x30, 0x00],
        });
        let err = decode(&encode(&ks).unwrap()).unwrap_err();
        assert!(err.contains("no-such-slot"));
        assert!(err.contains("unknown slot"));
    }

    #[test]
    fn decode_rejects_leaf_cert_for_aes_slot() {
        let mut ks = sample_keystore();
        // sample has an AES "storage-key" slot — a cert for it is invalid.
        ks.certificates.push(LeafCert {
            key_id: "storage-key".into(),
            certificate: vec![0x30, 0x00],
        });
        let err = decode(&encode(&ks).unwrap()).unwrap_err();
        assert!(err.contains("storage-key"));
        assert!(err.contains("requires an EC-P256 slot"));
    }

    #[test]
    fn decode_rejects_aes_with_anchor_public() {
        let mut ks = sample_keystore();
        ks.slots.push(KeySlot {
            key_id: "evil-aes-anchor".into(),
            key_kind: KEY_TYPE_AES_256,
            anchor_public_key: Some(vec![0u8; 65]),
            allowed_guests: None,
            allowed_ops: None,
        });
        let bytes = encode(&ks).unwrap();
        let err = decode(&bytes).unwrap_err();
        assert!(err.contains("evil-aes-anchor"));
        assert!(err.contains("AES keys are device-generated"));
    }

    #[test]
    fn decode_rejects_malformed_anchor_public() {
        let mut ks = sample_keystore();
        ks.slots.push(KeySlot {
            key_id: "malformed-anchor".into(),
            key_kind: KEY_TYPE_EC_P256,
            anchor_public_key: Some(vec![0x05; 65]), // wrong leading byte
            allowed_guests: None,
            allowed_ops: Some(vec![OP_VERIFY]),
        });
        let bytes = encode(&ks).unwrap();
        let err = decode(&bytes).unwrap_err();
        assert!(err.contains("malformed-anchor"));
        assert!(err.contains("uncompressed SEC1"));
    }

    #[test]
    fn ops_as_strings_translates() {
        let slot = device_generated_ec("test", "bali-vm-1");
        assert_eq!(
            slot.ops_as_strings().unwrap(),
            vec!["SIGN", "VERIFY", "GET_PUBKEY"],
        );
    }

    #[test]
    fn parsed_key_type_round_trip() {
        let ec = device_generated_ec("ec", "g");
        assert_eq!(ec.parsed_key_type(), Some(KeyType::EcP256));
        let aes = device_generated_aes("aes", "g");
        assert_eq!(aes.parsed_key_type(), Some(KeyType::Aes256));
    }
}
