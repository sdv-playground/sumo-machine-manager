//! Capability + authority-tier authorizer — the sumo-machine-manager side of
//! the SOVDd `Authorizer` seam.
//!
//! SOVDd computes the [`Capability`] a route requires and hands it to an
//! injected [`Authorizer`]; this implementation enforces, **at the verifier**,
//! that the issuer which *signed* the token is trusted for the *tier* of that
//! capability. So a token from an operational-tier issuer can never perform a
//! high-consequence op (factory-reset, vehicle reboot) even if it claims the
//! scope — and even if that issuer's signing key has been stolen, because the
//! ceiling is keyed to the issuer the signature binds the token to, not to what
//! the token claims. See `docs/design/authorization.md` §5.
//!
//! SOVDd ships only the trait; this lives here because the verb taxonomy and the
//! issuer→ceiling policy are vendor concerns. The trusted-issuer *keys* are
//! supplied at construction (a deployment reads them from its `HsmProvider` /
//! pinned roots); this type stays HSM-agnostic.

use async_trait::async_trait;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sovd_api::{AccessRequest, Authorizer, Capability, ClientContext};

/// Authority tier. A token may only exercise a capability whose tier is `<=` the
/// ceiling of the issuer that signed it. Order matters: `Operational <
/// HighConsequence`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Reads + routine OTA — mintable in-vehicle (onboard `jwt-mgr`), by a
    /// standalone tester, or online.
    Operational,
    /// Physical-consequence / irreversible ops (ecu-wipe, vehicle reboot,
    /// factory-reset, HSM keystore) — external authority only.
    HighConsequence,
}

/// The tier a capability requires.
pub fn capability_tier(cap: Capability) -> Tier {
    match cap {
        Capability::FactoryReset | Capability::ResetExecute => Tier::HighConsequence,
        _ => Tier::Operational,
    }
}

/// The scope string a capability requires; `None` means component scope alone
/// is enough (a plain read).
pub fn capability_scope(cap: Capability) -> Option<&'static str> {
    match cap {
        Capability::DataRead => Some("data:read"),
        Capability::DataWrite => Some("data:write"),
        Capability::OperationsExecute => Some("operations:execute"),
        Capability::ModesSet => Some("modes:set"),
        Capability::UpdateTransfer => Some("update:transfer"),
        Capability::UpdateExecute => Some("update:execute"),
        Capability::UpdateVerdict => Some("update:verdict"),
        Capability::ResetExecute => Some("reset:execute"),
        Capability::FactoryReset => Some("factory-reset"),
        Capability::Admin => Some("admin"),
        Capability::Read => None,
    }
}

/// A pinned trusted issuer and the maximum tier it may grant.
pub struct TrustedIssuer {
    /// The `kid` the minter stamps and the expected `iss` claim — both must name
    /// this issuer, and the signature must verify against [`Self::key`].
    pub id: String,
    /// Expected `aud` claim (this device / vehicle id) — the cross-target replay
    /// guard.
    pub audience: String,
    /// The issuer's verifying key (asymmetric).
    pub key: DecodingKey,
    /// The highest tier this issuer may grant.
    pub ceiling: Tier,
}

/// The injected authorizer: pins a set of trusted issuers (each with a ceiling)
/// and enforces issuer-tier → capability-tier, capability scope, and component
/// scope.
pub struct TieredAuthorizer {
    issuers: Vec<TrustedIssuer>,
}

impl TieredAuthorizer {
    pub fn new(issuers: Vec<TrustedIssuer>) -> Self {
        Self { issuers }
    }
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    scopes: Option<Vec<String>>,
}

impl Claims {
    fn into_scopes(self) -> Vec<String> {
        if let Some(arr) = self.scopes {
            arr
        } else if let Some(s) = self.scope {
            s.split_whitespace().map(String::from).collect()
        } else {
            Vec::new()
        }
    }
}

fn strip_bearer(header: Option<&str>) -> Result<&str, String> {
    header
        .and_then(|v| v.strip_prefix("Bearer ").map(str::trim))
        .filter(|t| !t.is_empty())
        .ok_or_else(|| "missing or malformed bearer token".to_string())
}

#[async_trait]
impl Authorizer for TieredAuthorizer {
    async fn authorize(&self, req: &AccessRequest<'_>) -> Result<ClientContext, String> {
        let token = strip_bearer(req.bearer)?;

        // Select the candidate issuer by the token's `kid` (key id). This is
        // unauthenticated until the signature verifies below against this exact
        // issuer's key — which is what binds the token to the issuer whose
        // ceiling then applies.
        let kid = decode_header(token)
            .map_err(|e| format!("invalid token header: {e}"))?
            .kid
            .ok_or("token is missing its `kid` (issuer)")?;
        let issuer = self
            .issuers
            .iter()
            .find(|i| i.id == kid)
            .ok_or_else(|| format!("untrusted issuer '{kid}'"))?;

        // Verify signature + exp/aud/iss against the pinned issuer key. After
        // this, the token is cryptographically bound to `issuer`. ES256 is the
        // pinned issuer alg — asymmetric only, so `HS*` is rejected (a verifying
        // key can never be misused as an HMAC secret; alg-confusion defence).
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&[&issuer.audience]);
        validation.set_issuer(&[&issuer.id]);
        validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
        let claims = decode::<Claims>(token, &issuer.key, &validation)
            .map_err(|e| format!("token verification failed: {e}"))?
            .claims;

        // Authority-tier ceiling — the crux. The issuer that genuinely signed
        // this token must be trusted for at least the capability's tier.
        let needed = capability_tier(req.capability);
        if issuer.ceiling < needed {
            return Err(format!(
                "issuer '{}' (ceiling {:?}) may not grant a {:?} capability",
                issuer.id, issuer.ceiling, needed
            ));
        }

        let ctx = ClientContext {
            subject: claims.sub.clone(),
            scopes: claims.into_scopes(),
        };

        // Component scope (C-031).
        if let Some(component) = req.component {
            if !ctx.can_access_component(component) {
                return Err(format!("token has no scope for component '{component}'"));
            }
        }
        // Capability (verb) scope.
        if let Some(scope) = capability_scope(req.capability) {
            if !ctx.scopes.iter().any(|s| s == scope) {
                return Err(format!("token lacks the '{scope}' capability"));
            }
        }
        Ok(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    /// A deterministic ES256 keypair from a small non-zero scalar — no RNG, so
    /// `issuer_keys(1)` and `issuer_keys(2)` are distinct, stable issuer keys.
    fn issuer_keys(seed: u8) -> (EncodingKey, DecodingKey) {
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};

        let mut scalar = [0u8; 32];
        scalar[31] = seed;
        let sk = SigningKey::from_bytes(&p256::FieldBytes::from(scalar)).expect("valid scalar");
        let priv_pem = sk.to_pkcs8_pem(LineEnding::LF).expect("pkcs8 pem");
        let pub_pem = sk
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("spki pem");
        (
            EncodingKey::from_ec_pem(priv_pem.as_bytes()).expect("encoding key"),
            DecodingKey::from_ec_pem(pub_pem.as_bytes()).expect("decoding key"),
        )
    }

    /// Mint an ES256 token: `kid`/`iss` name the issuer, signed by `key`.
    fn mint(key: &EncodingKey, issuer: &str, aud: &str, scopes: &[&str]) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(issuer.to_string());
        let claims = serde_json::json!({
            "sub": "operator",
            "iss": issuer,
            "aud": aud,
            "exp": 9_999_999_999u64,
            "scope": scopes.join(" "),
        });
        encode(&header, &claims, key).expect("mint")
    }

    fn access<'a>(
        bearer: &'a str,
        component: Option<&'a str>,
        cap: Capability,
    ) -> AccessRequest<'a> {
        AccessRequest {
            bearer: Some(bearer),
            method: &axum::http::Method::POST,
            path: "/test",
            component,
            capability: cap,
        }
    }

    fn two_tier_authorizer() -> (EncodingKey, EncodingKey, TieredAuthorizer) {
        let (op_enc, op_dec) = issuer_keys(1);
        let (ext_enc, ext_dec) = issuer_keys(2);
        let authz = TieredAuthorizer::new(vec![
            TrustedIssuer {
                id: "onboard".into(),
                audience: "vehicle-1".into(),
                key: op_dec,
                ceiling: Tier::Operational,
            },
            TrustedIssuer {
                id: "external".into(),
                audience: "vehicle-1".into(),
                key: ext_dec,
                ceiling: Tier::HighConsequence,
            },
        ]);
        (op_enc, ext_enc, authz)
    }

    // THE crux: an operational-tier issuer cannot grant a high-consequence
    // capability, even with the scope and a valid signature.
    #[tokio::test]
    async fn operational_issuer_cannot_grant_high_consequence() {
        let (op_enc, _ext_enc, authz) = two_tier_authorizer();
        let token = mint(&op_enc, "onboard", "vehicle-1", &["factory-reset"]);
        let bearer = format!("Bearer {token}");
        let err = authz
            .authorize(&access(&bearer, None, Capability::FactoryReset))
            .await
            .unwrap_err();
        assert!(err.contains("may not grant"), "{err}");
    }

    #[tokio::test]
    async fn external_issuer_grants_high_consequence() {
        let (_op_enc, ext_enc, authz) = two_tier_authorizer();
        let token = mint(&ext_enc, "external", "vehicle-1", &["factory-reset"]);
        let bearer = format!("Bearer {token}");
        let ctx = authz
            .authorize(&access(&bearer, None, Capability::FactoryReset))
            .await
            .expect("granted");
        assert_eq!(ctx.subject, "operator");
    }

    #[tokio::test]
    async fn operational_issuer_grants_operational() {
        let (op_enc, _ext_enc, authz) = two_tier_authorizer();
        let token = mint(
            &op_enc,
            "onboard",
            "vehicle-1",
            &["component:vm1", "data:read"],
        );
        let bearer = format!("Bearer {token}");
        let ctx = authz
            .authorize(&access(&bearer, Some("vm1"), Capability::DataRead))
            .await
            .expect("granted");
        assert!(ctx.scopes.iter().any(|s| s == "data:read"));
    }

    // Forge a high-tier `kid` but sign with the operational key — the signature
    // won't verify against the external issuer's key.
    #[tokio::test]
    async fn forged_high_tier_kid_fails_signature() {
        let (op_enc, _ext_enc, authz) = two_tier_authorizer();
        let token = mint(&op_enc, "external", "vehicle-1", &["factory-reset"]);
        let bearer = format!("Bearer {token}");
        let err = authz
            .authorize(&access(&bearer, None, Capability::FactoryReset))
            .await
            .unwrap_err();
        assert!(err.contains("verification failed"), "{err}");
    }

    #[tokio::test]
    async fn untrusted_issuer_rejected() {
        let (op_enc, _ext_enc, authz) = two_tier_authorizer();
        let token = mint(&op_enc, "rogue", "vehicle-1", &["data:read"]);
        let bearer = format!("Bearer {token}");
        let err = authz
            .authorize(&access(&bearer, None, Capability::DataRead))
            .await
            .unwrap_err();
        assert!(err.contains("untrusted issuer"), "{err}");
    }

    #[tokio::test]
    async fn missing_capability_scope_denied() {
        let (op_enc, _ext_enc, authz) = two_tier_authorizer();
        let token = mint(&op_enc, "onboard", "vehicle-1", &["component:vm1"]);
        let bearer = format!("Bearer {token}");
        let err = authz
            .authorize(&access(&bearer, Some("vm1"), Capability::DataRead))
            .await
            .unwrap_err();
        assert!(err.contains("lacks the 'data:read'"), "{err}");
    }

    #[tokio::test]
    async fn wrong_component_denied() {
        let (op_enc, _ext_enc, authz) = two_tier_authorizer();
        let token = mint(
            &op_enc,
            "onboard",
            "vehicle-1",
            &["component:other", "data:read"],
        );
        let bearer = format!("Bearer {token}");
        let err = authz
            .authorize(&access(&bearer, Some("vm1"), Capability::DataRead))
            .await
            .unwrap_err();
        assert!(err.contains("no scope for component 'vm1'"), "{err}");
    }

    #[tokio::test]
    async fn wrong_audience_rejected() {
        let (op_enc, _ext_enc, authz) = two_tier_authorizer();
        // Token minted for a different vehicle — the `aud` replay guard rejects.
        let token = mint(
            &op_enc,
            "onboard",
            "vehicle-2",
            &["component:vm1", "data:read"],
        );
        let bearer = format!("Bearer {token}");
        let err = authz
            .authorize(&access(&bearer, Some("vm1"), Capability::DataRead))
            .await
            .unwrap_err();
        assert!(err.contains("verification failed"), "{err}");
    }

    // A bad token must never crash the server — every malformed / garbage input
    // returns Err, never panics.
    #[tokio::test]
    async fn malformed_tokens_never_panic() {
        let (_op, _ext, authz) = two_tier_authorizer();
        let mut garbage: Vec<String> = vec![
            "".into(),
            "Bearer ".into(),
            "Bearer not-a-jwt".into(),
            "Bearer a.b".into(),
            "Bearer a.b.c".into(),
            "Bearer ...".into(),
            "Bearer eyJhbGciOiJFUzI1NiJ9".into(), // header only
            "Bearer eyJhbGciOiJIUzI1NiIsImtpZCI6Im9uYm9hcmQifQ.e30.AAAA".into(), // HS256 + kid
            "no-bearer-prefix".into(),
            "Bearer onboard".into(),
        ];
        garbage.push(format!("Bearer {}", "A".repeat(5000)));
        garbage.push("Bearer \u{1F980}.\u{1F980}.\u{1F980}".into());
        for t in &garbage {
            let req = AccessRequest {
                bearer: Some(t.as_str()),
                method: &axum::http::Method::POST,
                path: "/vehicle/v1/components/vm1/data",
                component: Some("vm1"),
                capability: Capability::DataRead,
            };
            // The point: this must NOT panic; it must return Err.
            assert!(
                authz.authorize(&req).await.is_err(),
                "garbage token {t:?} must be rejected, not accepted"
            );
        }
        // The no-header case.
        let req = AccessRequest {
            bearer: None,
            method: &axum::http::Method::POST,
            path: "/x",
            component: None,
            capability: Capability::DataRead,
        };
        assert!(authz.authorize(&req).await.is_err());
    }
}
