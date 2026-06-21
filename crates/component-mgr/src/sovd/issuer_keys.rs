//! Build a [`TieredAuthorizer`](super::authz::TieredAuthorizer) from the
//! device's HSM-provisioned token-issuer anchors — the deployment-side bridge
//! that lets [`super::authz`] stay HSM-agnostic.
//!
//! A deployment (e.g. supernova) supplies each issuer anchor's SPKI-DER public
//! key (`|id| hsm.get_public_key_der(id).ok()`) and each pinned CA root's DER
//! (`|id| hsm.get_trust_anchor_der(id).ok()`) plus the device's own id (its cert
//! CN), and gets back an authorizer that pins each issuer to its tier ceiling and
//! the delegation root for the delegated (`x5c`) path.

use hsm::payload::DELEGATION_ROOT_ANCHOR_ID;
use hsm::KeyRole;
use jsonwebtoken::DecodingKey;
use p256::ecdsa::VerifyingKey;
use p256::pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding};

use super::authz::{Tier, TieredAuthorizer, TrustedIssuer};

/// The token-issuer anchors a device pins, with the tier each may grant —
/// including the device's own in-vehicle minter (`jwt-signing`, Operational).
/// Each is resolved from the HSM by `key_id`; a slot the keystore didn't
/// provision is skipped, so the set self-trims to what the device actually holds.
const ISSUER_ANCHORS: &[(KeyRole, Tier)] = &[
    (KeyRole::FactoryResetIssuer, Tier::HighConsequence),
    (KeyRole::OperationalIssuer, Tier::Operational),
    // The device's own onboard minter — a mandatory device-generated slot, so the
    // device trusts its in-vehicle `jwt-mgr` for Operational tokens. Reboot stays
    // off the onboard path by minter policy (it never emits `reset:execute`), not
    // by tier. Absent → skipped, so this is safe on a rig with no onboard minter.
    (KeyRole::JwtSigning, Tier::Operational),
];

/// Convert an SPKI-DER EC-P256 public key — what
/// `HsmCryptoProvider::get_public_key_der` returns — into a jsonwebtoken
/// [`DecodingKey`].
fn decoding_key_from_spki_der(der: &[u8]) -> Result<DecodingKey, String> {
    let vk = VerifyingKey::from_public_key_der(der)
        .map_err(|e| format!("issuer key is not SPKI EC-P256: {e}"))?;
    let pem = vk
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| format!("re-encode issuer key: {e}"))?;
    DecodingKey::from_ec_pem(pem.as_bytes()).map_err(|e| format!("build decoding key: {e}"))
}

/// Build a [`TieredAuthorizer`] from the device's provisioned trust material.
///
/// `get_pubkey_der(key_id)` yields each issuer anchor's SPKI-DER public key, or
/// `None` if that slot isn't provisioned (skipped — a half-provisioned rig just
/// trusts fewer issuers). `get_trust_anchor_der(anchor_id)` yields a pinned CA
/// root's DER, or `None`; when it returns the delegation root, the delegated
/// (`x5c`) path is enabled with that root pinned. BOTH come from the same HSM
/// keystore the device installs at provisioning — never an out-of-band file.
/// `audience` is the device's own id (its cert CN), pinned as every token's
/// expected `aud` — the cross-target replay guard.
pub fn authorizer_from_anchors(
    get_pubkey_der: impl Fn(&str) -> Option<Vec<u8>>,
    get_trust_anchor_der: impl Fn(&str) -> Option<Vec<u8>>,
    audience: &str,
) -> Result<TieredAuthorizer, String> {
    let mut issuers = Vec::new();
    for &(role, ceiling) in ISSUER_ANCHORS {
        let Some(der) = get_pubkey_der(role.key_id()) else {
            continue;
        };
        let key = decoding_key_from_spki_der(&der)
            .map_err(|e| format!("issuer '{}': {e}", role.key_id()))?;
        issuers.push(TrustedIssuer {
            id: role.key_id().to_string(),
            audience: audience.to_string(),
            key,
            ceiling,
        });
    }
    let mut authz = TieredAuthorizer::new(issuers).with_aud(audience);
    // Pin the delegation root if the device provisioned one — the CA whose chain
    // a delegated (`x5c`) token must validate to. It rides the SAME keystore
    // channel as the issuer anchors above (Tower 1 provisions it into the HSM,
    // never an out-of-band file); its absence just leaves the delegated path off.
    if let Some(der) = get_trust_anchor_der(DELEGATION_ROOT_ANCHOR_ID) {
        let pem = cert_der_to_pem(&der)
            .map_err(|e| format!("delegation root '{DELEGATION_ROOT_ANCHOR_ID}': {e}"))?;
        authz = authz.with_pinned_root(pem);
    }
    Ok(authz)
}

/// Re-encode a DER X.509 certificate (as carried in the keystore's
/// `trust_anchors`) to the PEM that [`TieredAuthorizer::with_pinned_root`]
/// expects. Parsing here rejects a malformed anchor at load time rather than
/// deferring the failure to first delegated-token use.
fn cert_der_to_pem(der: &[u8]) -> Result<Vec<u8>, String> {
    use x509_cert::der::{Decode, EncodePem};
    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|e| format!("not a DER X.509 certificate: {e}"))?;
    cert.to_pem(x509_cert::der::pem::LineEnding::LF)
        .map(String::into_bytes)
        .map_err(|e| format!("re-encode as PEM: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePrivateKey;
    use sovd_api::{AccessRequest, Authorizer, Capability};

    #[test]
    fn onboard_jwt_signing_is_a_pinned_operational_issuer() {
        // The onboard minter (jwt-signing) must be in the trust list as an
        // Operational issuer — else the device would reject its own in-vehicle
        // tokens once the general path enforces auth. Reboot is kept off this
        // path at the minter, not by withholding trust.
        assert!(
            ISSUER_ANCHORS
                .iter()
                .any(|(r, t)| *r == KeyRole::JwtSigning && *t == Tier::Operational),
            "jwt-signing must be pinned as an Operational issuer"
        );
    }

    /// The well-known dev HC key (P-256 scalar=1) — the same key `sumo-dev-mint`
    /// signs with and that Tower provisions into the factory-reset-issuer
    /// anchor (`FACTORY_SIGNING_PUBLIC`).
    fn dev_hc() -> SigningKey {
        let mut s = [0u8; 32];
        s[31] = 1;
        SigningKey::from_bytes(&p256::FieldBytes::from(s)).unwrap()
    }

    fn factory_reset_token(sk: &SigningKey, kid: &str, aud: &str) -> String {
        let enc =
            EncodingKey::from_ec_pem(sk.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes()).unwrap();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(kid.to_string());
        let claims = serde_json::json!({
            "sub": "dev-operator", "iss": kid, "aud": aud,
            "exp": 9_999_999_999u64, "scope": "factory-reset",
        });
        encode(&header, &claims, &enc).unwrap()
    }

    fn req<'a>(bearer: &'a str, cap: Capability) -> AccessRequest<'a> {
        AccessRequest {
            bearer: Some(bearer),
            method: &axum::http::Method::POST,
            path: "/x",
            component: None,
            capability: cap,
        }
    }

    #[tokio::test]
    async fn authorizer_from_hc_anchor_accepts_a_dev_factory_reset_token() {
        let sk = dev_hc();
        let spki = sk.verifying_key().to_public_key_der().unwrap().into_vec();
        let hc = KeyRole::FactoryResetIssuer.key_id();

        let authz =
            authorizer_from_anchors(|id| (id == hc).then(|| spki.clone()), |_| None, "rig-1")
                .unwrap();

        let bearer = format!("Bearer {}", factory_reset_token(&sk, hc, "rig-1"));
        assert!(authz
            .authorize(&req(&bearer, Capability::FactoryReset))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn token_bound_to_another_device_is_rejected() {
        let sk = dev_hc();
        let spki = sk.verifying_key().to_public_key_der().unwrap().into_vec();
        let hc = KeyRole::FactoryResetIssuer.key_id();
        let authz =
            authorizer_from_anchors(|id| (id == hc).then(|| spki.clone()), |_| None, "rig-1")
                .unwrap();

        let bearer = format!("Bearer {}", factory_reset_token(&sk, hc, "other-rig"));
        assert!(authz
            .authorize(&req(&bearer, Capability::FactoryReset))
            .await
            .is_err());
    }

    #[test]
    fn unprovisioned_anchors_yield_an_empty_authorizer() {
        // No keys provisioned → builds cleanly, trusts no one (safe default).
        assert!(authorizer_from_anchors(|_| None, |_| None, "rig-1").is_ok());
    }

    /// Self-signed P-256 root DER — stands in for the delegation root the
    /// keystore provisions into `trust_anchors`.
    fn self_signed_root_der() -> Vec<u8> {
        use std::str::FromStr;
        use std::time::Duration;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::der::Encode;
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::spki::SubjectPublicKeyInfoOwned;
        use x509_cert::time::Validity;
        let key = SigningKey::random(&mut rand::rngs::OsRng);
        let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).unwrap();
        CertificateBuilder::new(
            Profile::Root,
            SerialNumber::new(&[1]).unwrap(),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            Name::from_str("CN=test delegation root").unwrap(),
            spki,
            &key,
        )
        .unwrap()
        .build::<p256::ecdsa::DerSignature>()
        .unwrap()
        .to_der()
        .unwrap()
    }

    #[test]
    fn provisioned_delegation_root_is_loaded_and_garbage_rejected() {
        let root_der = self_signed_root_der();
        let id = DELEGATION_ROOT_ANCHOR_ID;

        // A provisioned delegation root loads (DER -> PEM -> pinned) without error.
        assert!(authorizer_from_anchors(
            |_| None,
            |a| (a == id).then(|| root_der.clone()),
            "rig-1"
        )
        .is_ok());

        // No delegation root provisioned → still fine; delegated path just off.
        assert!(authorizer_from_anchors(|_| None, |_| None, "rig-1").is_ok());

        // A malformed trust anchor is rejected at LOAD, not deferred to first use.
        assert!(authorizer_from_anchors(
            |_| None,
            |a| (a == id).then(|| vec![0xDEu8, 0xAD]),
            "rig-1"
        )
        .is_err());
    }
}
