//! Build a [`TieredAuthorizer`](super::authz::TieredAuthorizer) from the
//! device's HSM-provisioned token-issuer anchors — the deployment-side bridge
//! that lets [`super::authz`] stay HSM-agnostic.
//!
//! A deployment (e.g. supernova) supplies each anchor's SPKI-DER public key
//! (`|id| hsm.get_public_key_der(id).ok()`) plus the device's own id (its cert
//! CN), and gets back an authorizer that pins each issuer to its tier ceiling.

use hsm::KeyRole;
use jsonwebtoken::DecodingKey;
use p256::ecdsa::VerifyingKey;
use p256::pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding};

use super::authz::{Tier, TieredAuthorizer, TrustedIssuer};

/// The token-issuer anchors a device pins, with the tier each may grant. The
/// in-vehicle minter (`jwt-signing`) is not listed: it is the device's own
/// Operational issuer and is added by the deployment when present.
const ISSUER_ANCHORS: &[(KeyRole, Tier)] = &[
    (KeyRole::HighConsequenceIssuer, Tier::HighConsequence),
    (KeyRole::OperationalIssuer, Tier::Operational),
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

/// Build a [`TieredAuthorizer`] from the device's provisioned issuer anchors.
///
/// `get_pubkey_der(key_id)` yields each anchor's SPKI-DER public key, or `None`
/// if that slot isn't provisioned (skipped — a half-provisioned rig just trusts
/// fewer issuers). `audience` is the device's own id (its cert CN), pinned as
/// every issuer's expected `aud` — the cross-target replay guard.
pub fn authorizer_from_anchors(
    get_pubkey_der: impl Fn(&str) -> Option<Vec<u8>>,
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
    Ok(TieredAuthorizer::new(issuers))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePrivateKey;
    use sovd_api::{AccessRequest, Authorizer, Capability};

    /// The well-known dev HC key (P-256 scalar=1) — the same key `sumo-dev-mint`
    /// signs with and that Tower provisions into the high-consequence-issuer
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
        let hc = KeyRole::HighConsequenceIssuer.key_id();

        let authz =
            authorizer_from_anchors(|id| (id == hc).then(|| spki.clone()), "rig-1").unwrap();

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
        let hc = KeyRole::HighConsequenceIssuer.key_id();
        let authz =
            authorizer_from_anchors(|id| (id == hc).then(|| spki.clone()), "rig-1").unwrap();

        let bearer = format!("Bearer {}", factory_reset_token(&sk, hc, "other-rig"));
        assert!(authz
            .authorize(&req(&bearer, Capability::FactoryReset))
            .await
            .is_err());
    }

    #[test]
    fn unprovisioned_anchors_yield_an_empty_authorizer() {
        // No keys provisioned → builds cleanly, trusts no one (safe default).
        assert!(authorizer_from_anchors(|_| None, "rig-1").is_ok());
    }
}
