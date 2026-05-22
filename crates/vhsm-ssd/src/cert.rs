//! CWT (CBOR Web Token, RFC 8392) certificate validation.
//!
//! Guest identity certs in v3 are CWTs signed by the device's
//! `ecu-signing` private key. The cert binds a principal name (cert
//! `sub`) to a guest-held identity pubkey (cert `cnf`); vhsm-ssd
//! validates the cert chain + proves the client holds the matching
//! private during AUTH.
//!
//! ## Claim set (RFC 8392 § 3.1.1 + RFC 8747 for `cnf`)
//!
//! | Claim | CBOR key | Meaning |
//! |---|---|---|
//! | iss | 1 | issuer ("device-<vin>") — informational |
//! | sub | 2 | subject (principal name, e.g. "vm2") |
//! | aud | 3 | audience — MUST be `"vhsm-ssd"` |
//! | exp | 4 | expiry (Unix seconds) |
//! | nbf | 5 | not-before (Unix seconds) |
//! | iat | 6 | issued-at (Unix seconds) |
//! | cti | 7 | CWT token ID (16 random bytes) |
//! | cnf | -65537 | Confirmation: proof-of-possession key |
//!
//! ## On-the-wire shape
//!
//! ```text
//! CWT = COSE_Sign1 = [ protected_hdr, unprotected_hdr, payload, signature ]
//!   where protected_hdr = bstr(map(1 → -7))           ; ES256
//!   where unprotected_hdr = {}                         ; empty
//!   where payload = bstr(claims_cbor_map)
//!   where signature = ES256(ecu-signing.priv, Sig_structure)
//! ```
//!
//! Validation is read-only against an externally-supplied
//! `ecu-signing` public point — this module does not touch the HSM
//! itself; the caller resolves the public point from
//! `HsmCryptoProvider::get_pubkey("ecu-signing")` once at daemon
//! startup and passes it in.

use std::time::{SystemTime, UNIX_EPOCH};

use ciborium::value::Value as CborValue;
use coset::iana::{Algorithm as CoseAlg, EllipticCurve as CoseEc};
use coset::{CborSerializable, CoseSign1};
use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
use p256::EncodedPoint;
use sha2::{Digest, Sha256};

use crate::proto::AuthFailReason;

/// CWT claim labels (RFC 8392 §3.1.1).
const CLAIM_ISS: i64 = 1;
const CLAIM_SUB: i64 = 2;
const CLAIM_AUD: i64 = 3;
const CLAIM_EXP: i64 = 4;
const CLAIM_NBF: i64 = 5;
#[allow(dead_code)] // Read on the off-box builder side (test_helpers); not consulted at validate time.
const CLAIM_IAT: i64 = 6;
#[allow(dead_code)] // Same — informational claim, not used in validation.
const CLAIM_CTI: i64 = 7;
/// RFC 8747 §3.1: confirmation method, "cnf".
const CLAIM_CNF: i64 = -65537;

/// COSE_Key labels for the pubkey we expect inside `cnf` (RFC 8152
/// §7).
const COSE_KEY_KTY: i64 = 1;
const COSE_KEY_ALG: i64 = 3;
const COSE_KEY_EC2_CRV: i64 = -1;
const COSE_KEY_EC2_X: i64 = -2;
const COSE_KEY_EC2_Y: i64 = -3;
const KTY_EC2: i64 = 2;

/// The single audience we accept. Different vhsm-ssd instances
/// across a fleet could use distinct audiences (e.g., per-region
/// shards); v1 hard-codes the single value.
pub const VHSM_AUDIENCE: &str = "vhsm-ssd";

/// Validated cert as returned by [`validate`]. Owns the bytes it
/// extracted — callers don't have to keep the original CWT slice
/// alive.
#[derive(Debug, Clone)]
pub struct ParsedCert {
    /// Subject — the principal name. Used as the IAM evaluator's
    /// identity input.
    pub subject: String,
    /// Issuer string from `iss`. Informational; not security-relevant
    /// once the signature is verified.
    pub issuer: String,
    /// Expiry as Unix seconds (the value of the `exp` claim).
    pub exp_unix: u64,
    /// `cnf` pubkey: 65-byte uncompressed SEC1 P-256 point
    /// (`0x04 || x || y`). The client proves possession of the
    /// corresponding private during AUTH by signing the daemon's
    /// nonce; see [`crate::auth`].
    pub cnf_pubkey: Vec<u8>,
    /// SHA-256 over the raw CWT bytes. Logged in the audit trail so
    /// a fleet operator can pin which cert was used.
    pub thumbprint: [u8; 32],
}

/// Validate a CWT against an `ecu-signing` public key.
///
/// Steps:
///   1. Parse the outer COSE_Sign1 structure.
///   2. Verify the ES256 signature against `ecu_signing_pub`.
///   3. CBOR-decode the payload as the claim map.
///   4. Check `aud == "vhsm-ssd"`.
///   5. Check `now ∈ [nbf, exp]`.
///   6. Extract `sub`, `iss`, `cnf.cose_key.ec2_pub`.
///
/// `ecu_signing_pub` is the 65-byte uncompressed SEC1 P-256 point
/// (`0x04 || x[32] || y[32]`). Callers typically read this from the
/// HSM via `HsmCryptoProvider::get_pubkey("ecu-signing")` once at
/// daemon startup.
///
/// `now` is the time used for exp/nbf checks; pass
/// `SystemTime::now()` in production. Lifted as a parameter so tests
/// can pin a deterministic clock.
pub fn validate(
    cwt_bytes: &[u8],
    ecu_signing_pub: &[u8],
    now: SystemTime,
) -> Result<ParsedCert, AuthFailReason> {
    // Step 1: parse COSE_Sign1.
    let cose = CoseSign1::from_slice(cwt_bytes).map_err(|_| AuthFailReason::InvalidParam)?;

    // Step 2: verify the ES256 signature against ecu-signing.
    let verifying_key = parse_p256_pub(ecu_signing_pub).ok_or(AuthFailReason::InvalidParam)?;
    cose.verify_signature(b"", |sig, data| {
        let signature =
            Signature::from_slice(sig).map_err(|_| AuthFailReason::BadCertSignature)?;
        verifying_key
            .verify(data, &signature)
            .map_err(|_| AuthFailReason::BadCertSignature)
    })?;

    // Step 3: CBOR-decode payload.
    let payload_bytes = cose.payload.as_deref().ok_or(AuthFailReason::InvalidParam)?;
    let payload_val: CborValue =
        ciborium::de::from_reader(payload_bytes).map_err(|_| AuthFailReason::InvalidParam)?;
    let claim_map = match payload_val {
        CborValue::Map(m) => m,
        _ => return Err(AuthFailReason::InvalidParam),
    };

    // Step 4: aud check.
    let aud: String = read_text_claim(&claim_map, CLAIM_AUD).ok_or(AuthFailReason::WrongAudience)?;
    if aud != VHSM_AUDIENCE {
        return Err(AuthFailReason::WrongAudience);
    }

    // Step 5: time checks. exp/nbf are required claims for our use.
    let exp = read_u64_claim(&claim_map, CLAIM_EXP).ok_or(AuthFailReason::CertExpired)?;
    let nbf = read_u64_claim(&claim_map, CLAIM_NBF).ok_or(AuthFailReason::CertExpired)?;
    let now_unix = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthFailReason::CertExpired)?
        .as_secs();
    if now_unix < nbf || now_unix >= exp {
        return Err(AuthFailReason::CertExpired);
    }

    // Step 6: extract subject + issuer + cnf pubkey.
    let subject = read_text_claim(&claim_map, CLAIM_SUB).ok_or(AuthFailReason::InvalidParam)?;
    if subject.is_empty() {
        return Err(AuthFailReason::InvalidParam);
    }
    let issuer = read_text_claim(&claim_map, CLAIM_ISS).unwrap_or_default();
    let cnf_pubkey = extract_cnf_ec2_pub(&claim_map).ok_or(AuthFailReason::InvalidParam)?;

    // Thumbprint = SHA-256 of the raw on-the-wire CWT bytes.
    let mut hasher = Sha256::new();
    hasher.update(cwt_bytes);
    let thumbprint: [u8; 32] = hasher.finalize().into();

    Ok(ParsedCert {
        subject,
        issuer,
        exp_unix: exp,
        cnf_pubkey,
        thumbprint,
    })
}

/// Parse a 65-byte uncompressed SEC1 P-256 point (`0x04 || x || y`)
/// into a verifying key.
fn parse_p256_pub(bytes: &[u8]) -> Option<VerifyingKey> {
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return None;
    }
    let point = EncodedPoint::from_bytes(bytes).ok()?;
    VerifyingKey::from_encoded_point(&point).ok()
}

/// Look up a text-shaped claim by integer key.
fn read_text_claim(map: &[(CborValue, CborValue)], key: i64) -> Option<String> {
    for (k, v) in map {
        if let CborValue::Integer(i) = k {
            let ki: i128 = (*i).into();
            if ki == key as i128 {
                if let CborValue::Text(s) = v {
                    return Some(s.clone());
                }
            }
        }
    }
    None
}

/// Look up an unsigned-integer claim by integer key.
fn read_u64_claim(map: &[(CborValue, CborValue)], key: i64) -> Option<u64> {
    for (k, v) in map {
        if let CborValue::Integer(i) = k {
            let ki: i128 = (*i).into();
            if ki == key as i128 {
                if let CborValue::Integer(n) = v {
                    let ni: i128 = (*n).into();
                    if (0..=u64::MAX as i128).contains(&ni) {
                        return Some(ni as u64);
                    }
                }
            }
        }
    }
    None
}

/// Pull the 65-byte uncompressed EC2 pubkey out of the `cnf`
/// confirmation claim. RFC 8747 §3.2: `cnf` is a map containing a
/// COSE_Key under label 1.
fn extract_cnf_ec2_pub(claims: &[(CborValue, CborValue)]) -> Option<Vec<u8>> {
    let cnf = claims.iter().find(|(k, _)| matches_int(k, CLAIM_CNF))?;
    let CborValue::Map(cnf_map) = &cnf.1 else { return None };
    // cnf must contain "COSE_Key" at label 1.
    let key_entry = cnf_map.iter().find(|(k, _)| matches_int(k, 1))?;
    let CborValue::Map(key_map) = &key_entry.1 else { return None };

    // Require: kty = EC2 (2), alg = ES256 (-7), crv = P-256 (1).
    let kty = read_int_map_val(key_map, COSE_KEY_KTY)?;
    if kty != KTY_EC2 {
        return None;
    }
    let crv = read_int_map_val(key_map, COSE_KEY_EC2_CRV)?;
    if crv != CoseEc::P_256 as i64 {
        return None;
    }
    // alg is optional in cnf COSE_Keys per RFC 8747; if present, must be ES256.
    if let Some(alg) = read_int_map_val(key_map, COSE_KEY_ALG) {
        if alg != CoseAlg::ES256 as i64 {
            return None;
        }
    }

    let x = read_bytes_map_val(key_map, COSE_KEY_EC2_X)?;
    let y = read_bytes_map_val(key_map, COSE_KEY_EC2_Y)?;
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    let mut out = Vec::with_capacity(65);
    out.push(0x04);
    out.extend_from_slice(&x);
    out.extend_from_slice(&y);
    Some(out)
}

fn matches_int(v: &CborValue, target: i64) -> bool {
    if let CborValue::Integer(i) = v {
        let ki: i128 = (*i).into();
        ki == target as i128
    } else {
        false
    }
}

fn read_int_map_val(map: &[(CborValue, CborValue)], key: i64) -> Option<i64> {
    for (k, v) in map {
        if matches_int(k, key) {
            if let CborValue::Integer(n) = v {
                let ni: i128 = (*n).into();
                return Some(ni as i64);
            }
        }
    }
    None
}

fn read_bytes_map_val(map: &[(CborValue, CborValue)], key: i64) -> Option<Vec<u8>> {
    for (k, v) in map {
        if matches_int(k, key) {
            if let CborValue::Bytes(b) = v {
                return Some(b.clone());
            }
        }
    }
    None
}

// ---- Test helpers (also reused by auth.rs tests) ----------------

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;
    use ciborium::value::Integer;
    use coset::{AsCborValue, CoseKey, CoseSign1Builder, HeaderBuilder};
    use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};

    /// Build a CWT signed by `signer_key` with the given claims.
    /// Returns (cwt_bytes, signer_pub_uncompressed).
    pub fn build_signed_cwt(
        signer_key: &SigningKey,
        subject: &str,
        audience: &str,
        cnf_pub_x: &[u8],
        cnf_pub_y: &[u8],
        not_before: u64,
        expires: u64,
    ) -> Vec<u8> {
        let cnf_cose_key = CoseKey {
            kty: coset::RegisteredLabel::Assigned(coset::iana::KeyType::EC2),
            alg: Some(coset::RegisteredLabelWithPrivate::Assigned(CoseAlg::ES256)),
            params: vec![
                (
                    coset::Label::Int(COSE_KEY_EC2_CRV),
                    CborValue::Integer(Integer::from(CoseEc::P_256 as i64)),
                ),
                (
                    coset::Label::Int(COSE_KEY_EC2_X),
                    CborValue::Bytes(cnf_pub_x.to_vec()),
                ),
                (
                    coset::Label::Int(COSE_KEY_EC2_Y),
                    CborValue::Bytes(cnf_pub_y.to_vec()),
                ),
            ],
            ..Default::default()
        };

        let cnf_val = cnf_cose_key.to_cbor_value().unwrap();
        // cnf = { 1: <COSE_Key> } per RFC 8747 §3.2
        let cnf_wrapped = CborValue::Map(vec![(CborValue::Integer(Integer::from(1i64)), cnf_val)]);

        let claims = CborValue::Map(vec![
            (
                CborValue::Integer(Integer::from(CLAIM_ISS)),
                CborValue::Text("device-test".to_string()),
            ),
            (
                CborValue::Integer(Integer::from(CLAIM_SUB)),
                CborValue::Text(subject.to_string()),
            ),
            (
                CborValue::Integer(Integer::from(CLAIM_AUD)),
                CborValue::Text(audience.to_string()),
            ),
            (
                CborValue::Integer(Integer::from(CLAIM_EXP)),
                CborValue::Integer(Integer::from(expires)),
            ),
            (
                CborValue::Integer(Integer::from(CLAIM_NBF)),
                CborValue::Integer(Integer::from(not_before)),
            ),
            (
                CborValue::Integer(Integer::from(CLAIM_IAT)),
                CborValue::Integer(Integer::from(not_before)),
            ),
            (
                CborValue::Integer(Integer::from(CLAIM_CTI)),
                CborValue::Bytes(vec![0xCA; 16]),
            ),
            (
                CborValue::Integer(Integer::from(CLAIM_CNF)),
                cnf_wrapped,
            ),
        ]);

        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&claims, &mut payload_bytes).unwrap();

        let cose = CoseSign1Builder::new()
            .protected(
                HeaderBuilder::new()
                    .algorithm(CoseAlg::ES256)
                    .build(),
            )
            .payload(payload_bytes)
            .create_signature(b"", |data| {
                let sig: Signature = signer_key.sign(data);
                sig.to_vec()
            })
            .build();
        cose.to_vec().unwrap()
    }

    pub fn sec1_pub_from_signing(sk: &SigningKey) -> Vec<u8> {
        let vk = sk.verifying_key();
        vk.to_encoded_point(false).as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::*;
    use super::*;
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;
    use std::time::Duration;

    fn fixed_time(unix: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(unix)
    }

    /// Generate a fresh (signer_key, signer_pub_uncompressed,
    /// principal_key, principal_x, principal_y) fixture.
    fn fresh_fixture() -> (SigningKey, Vec<u8>, SigningKey, Vec<u8>, Vec<u8>) {
        let signer = SigningKey::random(&mut OsRng);
        let signer_pub = sec1_pub_from_signing(&signer);
        let principal = SigningKey::random(&mut OsRng);
        let principal_pub_enc = principal.verifying_key().to_encoded_point(false);
        let bytes = principal_pub_enc.as_bytes();
        let x = bytes[1..33].to_vec();
        let y = bytes[33..65].to_vec();
        (signer, signer_pub, principal, x, y)
    }

    #[test]
    fn validates_a_well_formed_cwt() {
        let (signer, signer_pub, _principal, px, py) = fresh_fixture();
        let cwt = build_signed_cwt(&signer, "vm2", "vhsm-ssd", &px, &py, 1_000_000, 2_000_000);
        let parsed = validate(&cwt, &signer_pub, fixed_time(1_500_000)).unwrap();
        assert_eq!(parsed.subject, "vm2");
        assert_eq!(parsed.issuer, "device-test");
        assert_eq!(parsed.exp_unix, 2_000_000);
        assert_eq!(parsed.cnf_pubkey.len(), 65);
        assert_eq!(parsed.cnf_pubkey[0], 0x04);
        assert_eq!(&parsed.cnf_pubkey[1..33], &px[..]);
        assert_eq!(&parsed.cnf_pubkey[33..65], &py[..]);
        assert_eq!(parsed.thumbprint.len(), 32);
    }

    #[test]
    fn rejects_wrong_audience() {
        let (signer, signer_pub, _, px, py) = fresh_fixture();
        let cwt = build_signed_cwt(&signer, "vm2", "wrong-aud", &px, &py, 0, 9_999_999_999);
        let err = validate(&cwt, &signer_pub, fixed_time(1_500_000)).unwrap_err();
        assert_eq!(err, AuthFailReason::WrongAudience);
    }

    #[test]
    fn rejects_expired_cert() {
        let (signer, signer_pub, _, px, py) = fresh_fixture();
        let cwt = build_signed_cwt(&signer, "vm2", "vhsm-ssd", &px, &py, 0, 1_000);
        let err = validate(&cwt, &signer_pub, fixed_time(1_500_000)).unwrap_err();
        assert_eq!(err, AuthFailReason::CertExpired);
    }

    #[test]
    fn rejects_not_yet_valid_cert() {
        let (signer, signer_pub, _, px, py) = fresh_fixture();
        let cwt = build_signed_cwt(&signer, "vm2", "vhsm-ssd", &px, &py, 9_000_000, 10_000_000);
        let err = validate(&cwt, &signer_pub, fixed_time(1_500_000)).unwrap_err();
        assert_eq!(err, AuthFailReason::CertExpired);
    }

    #[test]
    fn rejects_tampered_payload() {
        let (signer, signer_pub, _, px, py) = fresh_fixture();
        let mut cwt = build_signed_cwt(&signer, "vm2", "vhsm-ssd", &px, &py, 0, 9_999_999_999);
        // Flip a byte in the middle of the CWT (likely in the
        // payload) and check the signature fails.
        let mid = cwt.len() / 2;
        cwt[mid] ^= 0xFF;
        let err = validate(&cwt, &signer_pub, fixed_time(1_500_000)).unwrap_err();
        // Could be BadCertSignature (if we tampered the payload but
        // the structure parses) or InvalidParam (if we tampered the
        // CBOR framing). Both are valid rejections.
        assert!(
            matches!(
                err,
                AuthFailReason::BadCertSignature | AuthFailReason::InvalidParam
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_wrong_signer() {
        let (signer, _signer_pub, _, px, py) = fresh_fixture();
        let imposter_pub = sec1_pub_from_signing(&SigningKey::random(&mut OsRng));
        let cwt = build_signed_cwt(&signer, "vm2", "vhsm-ssd", &px, &py, 0, 9_999_999_999);
        let err = validate(&cwt, &imposter_pub, fixed_time(1_500_000)).unwrap_err();
        assert_eq!(err, AuthFailReason::BadCertSignature);
    }

    #[test]
    fn rejects_malformed_cwt() {
        let (_, signer_pub, _, _, _) = fresh_fixture();
        let err = validate(b"not a cwt", &signer_pub, fixed_time(0)).unwrap_err();
        assert_eq!(err, AuthFailReason::InvalidParam);
    }

    #[test]
    fn rejects_empty_subject() {
        let (signer, signer_pub, _, px, py) = fresh_fixture();
        let cwt = build_signed_cwt(&signer, "", "vhsm-ssd", &px, &py, 0, 9_999_999_999);
        let err = validate(&cwt, &signer_pub, fixed_time(1_500_000)).unwrap_err();
        assert_eq!(err, AuthFailReason::InvalidParam);
    }

    #[test]
    fn rejects_malformed_signer_pub() {
        let (signer, _, _, px, py) = fresh_fixture();
        let cwt = build_signed_cwt(&signer, "vm2", "vhsm-ssd", &px, &py, 0, 9_999_999_999);
        let err = validate(&cwt, &[0u8; 64], fixed_time(1_500_000)).unwrap_err();
        assert_eq!(err, AuthFailReason::InvalidParam);
    }

    #[test]
    fn thumbprint_is_stable_across_calls() {
        let (signer, signer_pub, _, px, py) = fresh_fixture();
        let cwt = build_signed_cwt(&signer, "vm2", "vhsm-ssd", &px, &py, 0, 9_999_999_999);
        let a = validate(&cwt, &signer_pub, fixed_time(1_500_000)).unwrap();
        let b = validate(&cwt, &signer_pub, fixed_time(1_500_001)).unwrap();
        assert_eq!(a.thumbprint, b.thumbprint);
    }
}
