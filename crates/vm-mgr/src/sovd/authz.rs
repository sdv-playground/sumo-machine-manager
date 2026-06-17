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
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Header, Validation};
use serde::Deserialize;
use sovd_api::{AccessRequest, Authorizer, Capability, ClientContext};

// Delegated (`x5c`) path: chain verification lives in `delegation`; deriving the
// JWT verifying key from the verified leaf needs the x509/p256 SPKI surface.
use crate::sovd::delegation::verify_delegate_chain;

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
    /// When set, a token's `boot_id` claim must equal this — the device's
    /// current boot. Kills cross-boot replay (§7.1). `None` = no binding.
    expected_boot_id: Option<String>,
    /// When set, a vehicle-wide token's `epoch` claim must be `>=` this — the
    /// device's current vehicle-epoch floor (§7.3). `None` = no binding.
    expected_epoch: Option<u64>,
    /// When set, delegated (`x5c`) tokens are accepted: the leaf-first cert
    /// chain in the token header must terminate at this pinned root, and the
    /// leaf's delegated-rights extension caps what the token may exercise
    /// (§5/§6). `None` = delegation unsupported (a token bearing `x5c` is
    /// rejected — the device pins no delegation root).
    pinned_root_pem: Option<Vec<u8>>,
    /// The device's own id — the expected `aud` for *every* accepted token,
    /// pinned issuer or delegate alike (the cross-target replay guard). The
    /// pinned-issuer path reads `aud` per-issuer (all issuers share this id);
    /// the delegated path has no pinned issuer, so it enforces `aud` from here.
    /// Defaults in [`Self::new`] to the issuers' shared audience.
    aud: Option<String>,
}

impl TieredAuthorizer {
    pub fn new(issuers: Vec<TrustedIssuer>) -> Self {
        // The device audience is the same id on every pinned issuer (see
        // `issuer_keys::authorizer_from_anchors`, which pins each issuer's
        // `audience` to the device id). Derive it here so the delegated path —
        // which has no pinned issuer to read `aud` from — enforces the same
        // value. `with_aud` overrides it (e.g. a delegation-only authorizer
        // with no issuers).
        let aud = issuers.first().map(|i| i.audience.clone());
        Self {
            issuers,
            expected_boot_id: None,
            expected_epoch: None,
            pinned_root_pem: None,
            aud,
        }
    }

    /// Pin the delegation root: enables the delegated (`x5c`) path. A token
    /// whose header carries a cert chain is then verified against this root
    /// (root-pinning + path + signature + validity, via
    /// [`verify_delegate_chain`]), and the leaf's delegated-rights extension
    /// caps what it may grant. Omit to refuse all delegated tokens.
    pub fn with_pinned_root(mut self, pem: Vec<u8>) -> Self {
        self.pinned_root_pem = Some(pem);
        self
    }

    /// Set the device audience explicitly — the expected `aud` for every
    /// accepted token. Use this when there are no pinned issuers to derive it
    /// from (a delegation-only authorizer), or to override the derived value.
    pub fn with_aud(mut self, aud: impl Into<String>) -> Self {
        self.aud = Some(aud.into());
        self
    }

    /// Bind accepted tokens to the device's current boot: a token whose
    /// `boot_id` claim doesn't equal `boot_id` is rejected as stale (§7.1) — a
    /// token sniffed before a reboot is dead after it. Omit for no binding.
    pub fn with_boot_id(mut self, boot_id: impl Into<String>) -> Self {
        self.expected_boot_id = Some(boot_id.into());
        self
    }

    /// Bind accepted vehicle-wide tokens to the current vehicle-epoch (§7.3): a
    /// token whose `epoch` claim is below the device's epoch is rejected as
    /// stale, and one missing the claim is rejected. The epoch is a monotonic
    /// floor the master only ratchets up (§7.2), so this is the cross-boot
    /// freshness guard for grants that span ECUs and so can't name one ECU's
    /// `boot_id`. Omit for no binding.
    pub fn with_epoch(mut self, epoch: u64) -> Self {
        self.expected_epoch = Some(epoch);
        self
    }

    /// Freshness gate shared by both verification paths (pinned-issuer and
    /// delegated), so the boot_id + epoch rules have exactly ONE implementation
    /// and can never drift apart. Behaviour is identical to the formerly-inline
    /// block in [`Self::authorize`].
    ///
    /// Freshness (§7.1): when the device pins its current boot, a token must
    /// name it — one minted for an earlier boot is stale after a reboot, so a
    /// sniffed token dies at the next reboot. (Cross-boot replay guard;
    /// intra-boot replay would need a `jti` cache, out of scope here.)
    ///
    /// Vehicle-wide freshness (§7.3): when the device pins its current
    /// vehicle-epoch, a vehicle-wide token must carry an `epoch` claim at least
    /// that high. The epoch is a monotonic floor the master ratchets up (§7.2
    /// "never accept an epoch older than its current"), so a token minted
    /// against a superseded epoch is stale — the cross-boot guard for grants
    /// that span ECUs (which can't name one ECU's `boot_id`). A token ahead of
    /// the floor is fine (this device merely lags the master).
    fn check_freshness(&self, boot_id: Option<&str>, epoch: Option<u64>) -> Result<(), String> {
        if let Some(expected) = &self.expected_boot_id {
            if boot_id != Some(expected.as_str()) {
                return Err(
                    "stale token: boot_id does not match the device's current boot".to_string(),
                );
            }
        }

        if let Some(expected) = self.expected_epoch {
            match epoch {
                Some(epoch) if epoch >= expected => {}
                Some(_) => {
                    return Err(
                        "stale token: vehicle-epoch is older than the device's current epoch"
                            .to_string(),
                    )
                }
                None => return Err("vehicle-wide token is missing its `epoch` claim".to_string()),
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    /// Per-boot freshness binding (§7.1) — the target's `boot_id` at mint time.
    #[serde(default)]
    boot_id: Option<String>,
    /// Vehicle-wide freshness binding (§7.3) — the vehicle-epoch a vehicle-wide
    /// token was minted against.
    #[serde(default)]
    epoch: Option<u64>,
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

        let header = decode_header(token).map_err(|e| format!("invalid token header: {e}"))?;

        // A token bearing a cert chain (`x5c`) is a delegate's: its authority
        // rides in the leaf's cert, not in a pinned issuer. Route it to the
        // delegated path. (If we pin no delegation root, we trust no delegate —
        // reject rather than silently falling through to the pinned-issuer path,
        // which would just fail with "untrusted issuer" anyway.)
        if header.x5c.is_some() {
            let Some(pinned_root) = self.pinned_root_pem.as_deref() else {
                return Err("delegation not configured".to_string());
            };
            return self.authorize_delegated(token, &header, pinned_root, req);
        }

        // Select the candidate issuer by the token's `kid` (key id). This is
        // unauthenticated until the signature verifies below against this exact
        // issuer's key — which is what binds the token to the issuer whose
        // ceiling then applies.
        let kid = header.kid.ok_or("token is missing its `kid` (issuer)")?;
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

        // Freshness (§7.1 boot_id / §7.3 vehicle-epoch) — shared with the
        // delegated path via one helper so the two can't drift.
        self.check_freshness(claims.boot_id.as_deref(), claims.epoch)?;

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

impl TieredAuthorizer {
    /// The delegated (`x5c`) verification path. The token bears a leaf-first
    /// cert chain; the leaf's delegated-rights extension is the ceiling on what
    /// the token may exercise — there is NO pinned issuer and NO issuer-tier
    /// ceiling here. The trust chain is:
    ///
    /// 1. the chain verifies to the pinned root (root-pinning + path + signature
    ///    + validity) — done by [`verify_delegate_chain`];
    /// 2. the JWT is verified against the *verified leaf's* public key (so the
    ///    presenter holds the leaf's private key), with the device `aud`;
    /// 3. the token may only exercise a capability whose scope the *leaf's cert*
    ///    grants — a delegate cannot mint beyond what the root vouched for.
    fn authorize_delegated(
        &self,
        token: &str,
        header: &Header,
        pinned_root: &[u8],
        req: &AccessRequest<'_>,
    ) -> Result<ClientContext, String> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use p256::pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding};
        use x509_cert::der::{Decode, Encode};

        // (a) `x5c` is standard-base64 of DER, leaf-first (RFC 7515 §4.1.6).
        let x5c = header
            .x5c
            .as_ref()
            .ok_or("delegated token is missing its `x5c` chain")?;
        let chain_ders: Vec<Vec<u8>> = x5c
            .iter()
            .map(|b64| B64.decode(b64))
            .collect::<Result<_, _>>()
            .map_err(|e| format!("malformed `x5c` (not standard-base64 DER): {e}"))?;

        // (b) Delegation is the *cable-connected workshop* path: an operator is
        // physically present, so a usable wall clock is a reasonable assumption
        // and we verify the chain's validity window against `now`. The
        // OTA/clockless paths never use delegation — they go through pinned
        // issuers above, whose freshness comes from boot_id/epoch, not a clock.
        let now = rustls::pki_types::UnixTime::now();

        // (c) THE chain trust decision: root-pinning + path building + signature
        // + validity, plus the leaf's granted scopes. We do not re-implement any
        // of it.
        let authority = verify_delegate_chain(&chain_ders, pinned_root, now)
            .map_err(|e| format!("delegate chain rejected: {e}"))?;

        // (d) Derive the JWT verifying key from the *verified* leaf's SPKI — the
        // token must be signed by the key the root just vouched for, nothing
        // else. (Mirror `issuer_keys::decoding_key_from_spki_der`: SPKI-DER ->
        // P-256 public key -> PEM -> jsonwebtoken DecodingKey.)
        let leaf = x509_cert::Certificate::from_der(&authority.leaf_der)
            .map_err(|e| format!("verified leaf did not re-parse: {e}"))?;
        let spki_der = leaf
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|e| format!("leaf SPKI re-encode failed: {e}"))?;
        let leaf_pub = p256::PublicKey::from_public_key_der(&spki_der)
            .map_err(|e| format!("leaf key is not EC-P256: {e}"))?;
        let leaf_pem = leaf_pub
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| format!("leaf key re-encode failed: {e}"))?;
        let leaf_key = DecodingKey::from_ec_pem(leaf_pem.as_bytes())
            .map_err(|e| format!("build leaf decoding key: {e}"))?;

        // (e) Verify the token against the leaf key. ES256 only (asymmetric, so
        // `HS*` is rejected — alg-confusion defence). The device `aud` is the
        // same cross-target replay guard the pinned-issuer path enforces; there
        // is NO pinned issuer here, so `iss` is NOT pinned.
        let device_aud = self
            .aud
            .as_deref()
            .ok_or("authorizer has no device audience configured for delegation")?;
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&[device_aud]);
        validation.set_required_spec_claims(&["exp", "aud", "sub"]);
        let claims = decode::<Claims>(token, &leaf_key, &validation)
            .map_err(|e| format!("token verification failed: {e}"))?
            .claims;

        // (f) Freshness — the SAME helper the pinned-issuer path uses.
        self.check_freshness(claims.boot_id.as_deref(), claims.epoch)?;

        // (g) Identity + the token's own requested scopes.
        let granted_scopes = authority.granted_scopes;
        let ctx = ClientContext {
            subject: claims.sub.clone(),
            scopes: claims.into_scopes(),
        };

        // (h) Component scope (C-031) + capability (verb) scope — identical to
        // the pinned-issuer path.
        if let Some(component) = req.component {
            if !ctx.can_access_component(component) {
                return Err(format!("token has no scope for component '{component}'"));
            }
        }
        if let Some(scope) = capability_scope(req.capability) {
            if !ctx.scopes.iter().any(|s| s == scope) {
                return Err(format!("token lacks the '{scope}' capability"));
            }

            // (i) THE escalation ceiling — the crux of delegation. The token may
            // carry the scope and the chain may be valid, but the delegate may
            // only exercise a capability its *certificate* was granted the right
            // to. A workshop cert granting `update:transfer` can never have a
            // token it signs perform `reset:execute`, even if the operator asks.
            // The cert's granted scopes ARE the ceiling (no issuer-tier here).
            if !granted_scopes.iter().any(|g| g == scope) {
                return Err(format!(
                    "delegate's certificate does not authorise granting '{scope}'"
                ));
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

    #[tokio::test]
    async fn boot_id_binding_rejects_stale_and_missing() {
        let (enc, dec) = issuer_keys(2);
        let authz = TieredAuthorizer::new(vec![TrustedIssuer {
            id: "external".into(),
            audience: "vehicle-1".into(),
            key: dec,
            ceiling: Tier::HighConsequence,
        }])
        .with_boot_id("boot-42");

        let token = |boot: Option<&str>| {
            let mut header = Header::new(Algorithm::ES256);
            header.kid = Some("external".to_string());
            let mut claims = serde_json::json!({
                "sub": "op", "iss": "external", "aud": "vehicle-1",
                "exp": 9_999_999_999u64, "scope": "factory-reset",
            });
            if let Some(b) = boot {
                claims["boot_id"] = serde_json::json!(b);
            }
            format!("Bearer {}", encode(&header, &claims, &enc).unwrap())
        };

        // Fresh: boot_id names the live boot → accepted.
        let fresh = token(Some("boot-42"));
        assert!(authz
            .authorize(&access(&fresh, None, Capability::FactoryReset))
            .await
            .is_ok());
        // Stale: a different (earlier) boot → rejected.
        let stale = token(Some("boot-7"));
        assert!(authz
            .authorize(&access(&stale, None, Capability::FactoryReset))
            .await
            .is_err());
        // Missing boot_id while the device pins one → rejected.
        let none = token(None);
        assert!(authz
            .authorize(&access(&none, None, Capability::FactoryReset))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn epoch_binding_accepts_fresh_rejects_stale_and_missing() {
        let (enc, dec) = issuer_keys(2);
        let authz = TieredAuthorizer::new(vec![TrustedIssuer {
            id: "external".into(),
            audience: "vehicle-1".into(),
            key: dec,
            ceiling: Tier::HighConsequence,
        }])
        .with_epoch(5);

        let token = |epoch: Option<u64>| {
            let mut header = Header::new(Algorithm::ES256);
            header.kid = Some("external".to_string());
            let mut claims = serde_json::json!({
                "sub": "op", "iss": "external", "aud": "vehicle-1",
                "exp": 9_999_999_999u64, "scope": "factory-reset",
            });
            if let Some(e) = epoch {
                claims["epoch"] = serde_json::json!(e);
            }
            format!("Bearer {}", encode(&header, &claims, &enc).unwrap())
        };

        // Fresh: epoch == the floor → accepted.
        let fresh = token(Some(5));
        assert!(authz
            .authorize(&access(&fresh, None, Capability::FactoryReset))
            .await
            .is_ok());
        // Ahead of the floor (this device lags the master) → still accepted.
        let ahead = token(Some(6));
        assert!(authz
            .authorize(&access(&ahead, None, Capability::FactoryReset))
            .await
            .is_ok());
        // Stale: an epoch below the floor (superseded by a bump) → rejected.
        let stale = token(Some(4));
        assert!(authz
            .authorize(&access(&stale, None, Capability::FactoryReset))
            .await
            .is_err());
        // Missing epoch while the device pins one → rejected.
        let none = token(None);
        assert!(authz
            .authorize(&access(&none, None, Capability::FactoryReset))
            .await
            .is_err());
    }

    // -----------------------------------------------------------------------
    // Delegated (`x5c`) path — a delegate presents a cert chain to a pinned
    // root, and the cert's delegated-rights extension is the ceiling on what
    // tokens it signs may exercise. The JWT is verified against the verified
    // leaf's key (no pinned issuer). See `docs/design/authorization.md` §5/§6.
    // -----------------------------------------------------------------------
    mod delegated {
        use super::super::*;
        use super::access;
        use jsonwebtoken::{encode, EncodingKey, Header};

        use std::str::FromStr;
        use std::time::Duration;

        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use const_oid::db::rfc5280::ID_KP_CLIENT_AUTH;
        use p256::ecdsa::{DerSignature, SigningKey};
        use p256::pkcs8::{EncodePrivateKey, LineEnding};
        use rand::rngs::OsRng;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::der::{Encode, EncodePem};
        use x509_cert::ext::pkix::ExtendedKeyUsage;
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::spki::SubjectPublicKeyInfoOwned;
        use x509_cert::time::Validity;
        use x509_cert::Certificate as X509Certificate;

        use crate::sovd::delegated_rights::DelegatedRightsExt;

        const DEVICE_AUD: &str = "vehicle-1";

        fn one_hour() -> Validity {
            Validity::from_now(Duration::from_secs(3600)).unwrap()
        }

        /// PEM of a self-signed root for `ca_key`/`ca_name` (mirrors
        /// `delegation::tests::ca_root_pem`).
        fn ca_root_pem(ca_key: &SigningKey, ca_name: &Name) -> Vec<u8> {
            let spki = SubjectPublicKeyInfoOwned::from_key(*ca_key.verifying_key()).unwrap();
            let cert: X509Certificate = CertificateBuilder::new(
                Profile::Root,
                SerialNumber::new(&[1]).unwrap(),
                one_hour(),
                ca_name.clone(),
                spki,
                ca_key,
            )
            .unwrap()
            .build::<DerSignature>()
            .unwrap();
            cert.to_pem(x509_cert::der::pem::LineEnding::LF)
                .unwrap()
                .into_bytes()
        }

        /// Issue a delegate leaf signed by `ca_key`/`ca_name` over `leaf_key`'s
        /// public half, with the clientAuth EKU and an optional delegated-rights
        /// extension carrying `scopes`. Returns the leaf DER. The caller keeps
        /// `leaf_key` so it can sign the JWT with the leaf's private half
        /// (mirrors `delegation::tests::issue_leaf`, but the key is provided so
        /// we can mint with it).
        fn issue_leaf(
            ca_key: &SigningKey,
            ca_name: &Name,
            leaf_key: &SigningKey,
            scopes: Option<&str>,
        ) -> Vec<u8> {
            let spki = SubjectPublicKeyInfoOwned::from_key(*leaf_key.verifying_key()).unwrap();
            let mut builder = CertificateBuilder::new(
                Profile::Leaf {
                    issuer: ca_name.clone(),
                    enable_key_agreement: false,
                    enable_key_encipherment: false,
                },
                SerialNumber::new(&[2]).unwrap(),
                one_hour(),
                Name::from_str("CN=workshop delegate").unwrap(),
                spki,
                ca_key,
            )
            .unwrap();
            builder
                .add_extension(&ExtendedKeyUsage(vec![ID_KP_CLIENT_AUTH]))
                .unwrap();
            if let Some(s) = scopes {
                builder
                    .add_extension(&DelegatedRightsExt(s.to_string()))
                    .unwrap();
            }
            builder.build::<DerSignature>().unwrap().to_der().unwrap()
        }

        /// Mint an ES256 token signed by `signing_key`, carrying `leaf_der` as
        /// the single-element `x5c` (standard-base64 of DER, per RFC 7515). No
        /// `kid` — the delegated path keys off `x5c`, not a pinned issuer. The
        /// signing key is decoupled from the cert so a "wrong key" test can sign
        /// with a non-leaf key while presenting the leaf's cert.
        fn mint_delegated(
            signing_key: &SigningKey,
            leaf_der: &[u8],
            aud: &str,
            scope: &str,
        ) -> String {
            let enc = EncodingKey::from_ec_pem(
                signing_key.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes(),
            )
            .unwrap();
            let mut header = Header::new(Algorithm::ES256);
            header.x5c = Some(vec![B64.encode(leaf_der)]);
            let claims = serde_json::json!({
                "sub": "workshop-operator",
                "aud": aud,
                "exp": 9_999_999_999u64,
                "scope": scope,
            });
            encode(&header, &claims, &enc).unwrap()
        }

        /// An authorizer that pins `root_pem` and the device audience, trusting
        /// NO pinned issuers (delegation-only — proves the delegated path stands
        /// on its own, with the cert as the sole authority).
        fn delegated_authorizer(root_pem: Vec<u8>) -> TieredAuthorizer {
            TieredAuthorizer::new(vec![])
                .with_aud(DEVICE_AUD.to_string())
                .with_pinned_root(root_pem)
        }

        /// THE test: the cert grants only `update:transfer`, but the operator
        /// over-asks — the token claims `reset:execute`. The chain is valid and
        /// the token genuinely carries the scope, yet authorization MUST fail,
        /// because the delegate's *certificate* does not authorise granting
        /// `reset:execute`. The cert is the ceiling, not the token's claims.
        #[tokio::test]
        async fn delegate_cannot_exceed_its_granted_scopes() {
            let ca_key = SigningKey::random(&mut OsRng);
            let ca_name = Name::from_str("CN=workshop root").unwrap();
            let root_pem = ca_root_pem(&ca_key, &ca_name);
            let leaf_key = SigningKey::random(&mut OsRng);
            // Cert grants ONLY update:transfer.
            let leaf = issue_leaf(&ca_key, &ca_name, &leaf_key, Some("update:transfer"));

            // Token over-asks: claims reset:execute (+ component:rt) anyway.
            let token = mint_delegated(&leaf_key, &leaf, DEVICE_AUD, "reset:execute component:rt");
            let bearer = format!("Bearer {token}");
            let authz = delegated_authorizer(root_pem);

            let err = authz
                .authorize(&access(&bearer, Some("rt"), Capability::ResetExecute))
                .await
                .expect_err("a delegate may not exceed its cert's granted scopes");
            // Fails for the RIGHT reason: the escalation (granted-scopes) check,
            // NOT the chain (it verified) and NOT the verb-scope check (the token
            // DOES carry reset:execute).
            assert!(
                err.contains("does not authorise granting 'reset:execute'"),
                "must reject at the granted-scopes ceiling, got: {err}"
            );
        }

        /// Same shape, but now the cert DOES grant `reset:execute` (alongside
        /// `update:transfer`). The token claims `reset:execute component:rt`;
        /// the delegate is within its ceiling, so `ResetExecute` on `rt` is Ok.
        #[tokio::test]
        async fn delegate_granted_reset_is_authorized() {
            let ca_key = SigningKey::random(&mut OsRng);
            let ca_name = Name::from_str("CN=workshop root").unwrap();
            let root_pem = ca_root_pem(&ca_key, &ca_name);
            let leaf_key = SigningKey::random(&mut OsRng);
            let leaf = issue_leaf(
                &ca_key,
                &ca_name,
                &leaf_key,
                Some("reset:execute update:transfer"),
            );

            let token = mint_delegated(&leaf_key, &leaf, DEVICE_AUD, "reset:execute component:rt");
            let bearer = format!("Bearer {token}");
            let authz = delegated_authorizer(root_pem);

            let ctx = authz
                .authorize(&access(&bearer, Some("rt"), Capability::ResetExecute))
                .await
                .expect("a delegate within its cert's grant is authorized");
            assert_eq!(ctx.subject, "workshop-operator");
            assert!(ctx.scopes.iter().any(|s| s == "reset:execute"));
        }

        /// Root pinning on the delegated path: a valid delegate token, but the
        /// authorizer pins a DIFFERENT root. `verify_delegate_chain` cannot
        /// build a path to the pinned root → rejected before any JWT work.
        #[tokio::test]
        async fn delegated_token_under_wrong_root_rejected() {
            let ca_a = SigningKey::random(&mut OsRng);
            let name_a = Name::from_str("CN=root A").unwrap();
            let leaf_key = SigningKey::random(&mut OsRng);
            let leaf = issue_leaf(&ca_a, &name_a, &leaf_key, Some("reset:execute"));
            let token = mint_delegated(&leaf_key, &leaf, DEVICE_AUD, "reset:execute component:rt");
            let bearer = format!("Bearer {token}");

            // Pin an unrelated root B.
            let ca_b = SigningKey::random(&mut OsRng);
            let name_b = Name::from_str("CN=root B").unwrap();
            let authz = delegated_authorizer(ca_root_pem(&ca_b, &name_b));

            let err = authz
                .authorize(&access(&bearer, Some("rt"), Capability::ResetExecute))
                .await
                .expect_err("a delegate under root A must not verify against pinned root B");
            assert!(
                err.contains("pinned root"),
                "wrong-root rejection must come from the chain check, got: {err}"
            );
        }

        /// The leaf key must be the JWT signing key. `x5c` carries leaf A's
        /// cert (validly chained), but the JWT is signed by a DIFFERENT key →
        /// the signature can't verify against the leaf's public key → rejected.
        #[tokio::test]
        async fn delegated_token_signed_by_non_leaf_key_rejected() {
            let ca_key = SigningKey::random(&mut OsRng);
            let ca_name = Name::from_str("CN=workshop root").unwrap();
            let root_pem = ca_root_pem(&ca_key, &ca_name);
            let leaf_key = SigningKey::random(&mut OsRng);
            let leaf = issue_leaf(
                &ca_key,
                &ca_name,
                &leaf_key,
                Some("reset:execute update:transfer"),
            );

            // Sign the JWT with an UNRELATED key, but present the real leaf cert.
            let imposter = SigningKey::random(&mut OsRng);
            let token = mint_delegated(&imposter, &leaf, DEVICE_AUD, "reset:execute component:rt");
            let bearer = format!("Bearer {token}");
            let authz = delegated_authorizer(root_pem);

            let err = authz
                .authorize(&access(&bearer, Some("rt"), Capability::ResetExecute))
                .await
                .expect_err("a JWT not signed by the leaf key must be rejected");
            assert!(
                err.contains("token verification failed"),
                "must reject at JWT signature verification against the leaf key, got: {err}"
            );
        }

        /// The existing pinned-issuer path is untouched by the `x5c` branch: a
        /// classic token (no `x5c`, signed by a pinned issuer) authorizes exactly
        /// as before. Reuses the two-tier fixture from the parent module.
        #[tokio::test]
        async fn pinned_issuer_path_unaffected() {
            let (op_enc, _ext_enc, authz) = super::two_tier_authorizer();
            let token = super::mint(
                &op_enc,
                "onboard",
                "vehicle-1",
                &["component:vm1", "data:read"],
            );
            let bearer = format!("Bearer {token}");
            let ctx = authz
                .authorize(&access(&bearer, Some("vm1"), Capability::DataRead))
                .await
                .expect("classic pinned-issuer token still authorizes");
            assert_eq!(ctx.subject, "operator");
            assert!(ctx.scopes.iter().any(|s| s == "data:read"));
        }
    }
}
