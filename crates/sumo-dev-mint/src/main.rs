//! Dev SOVD capability-token minter.
//!
//! Signs tokens with the well-known dev key (P-256 `scalar = 1`, identical to
//! `hsm::payload::FACTORY_SIGNING_SCALAR`; its public half is the generator G =
//! `FACTORY_SIGNING_PUBLIC`, which dev rigs provision into the
//! `high-consequence-issuer` anchor). The key is public *by design* — any dev
//! tooling can mint a reset token, so a dev rig is always factory-resettable
//! even if Tower 1's storage is lost. NOT for production: there the workshop /
//! Tower-1 minter signs with a real, secret HighConsequence root.
//!
//! Token shape matches `vm-mgr::sovd::authz::TieredAuthorizer`: ES256, header
//! `kid` = `iss` = the issuer id, `aud` = the device id, and a space-delimited
//! `scope` carrying the capability (default `factory-reset`, the string
//! `authz::capability_scope(Capability::FactoryReset)` returns).

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use clap::Parser;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use serde::Serialize;

/// The well-known dev signing scalar — P-256 `scalar = 1` (mirrors
/// `hsm::payload::FACTORY_SIGNING_SCALAR`; a test pins the match). Public by
/// design — the dev "start over" guarantee, not a secret.
fn dev_signing_scalar() -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = 1;
    s
}

#[derive(Parser)]
#[command(
    name = "sumo-dev-mint",
    about = "Mint a dev SOVD capability token (well-known key; dev rigs only)"
)]
struct Cli {
    /// `aud` claim — the device / vehicle id the token is bound to (replay guard).
    #[arg(long)]
    device: String,
    /// Capability scope to grant (default mints a factory-reset token).
    #[arg(long, default_value = "factory-reset")]
    capability: String,
    /// `iss` claim + JWT `kid` — must name the issuer the device pins.
    #[arg(long, default_value = "high-consequence-issuer")]
    issuer: String,
    /// `sub` claim — the operator identity (dev placeholder).
    #[arg(long, default_value = "dev-operator")]
    subject: String,
    /// Token lifetime, seconds.
    #[arg(long, default_value_t = 900)]
    ttl_secs: u64,
}

#[derive(Serialize)]
struct Claims {
    sub: String,
    iss: String,
    aud: String,
    iat: u64,
    exp: u64,
    scope: String,
}

fn mint(
    scalar: &[u8; 32],
    issuer: &str,
    subject: &str,
    aud: &str,
    scope: &str,
    iat: u64,
    ttl_secs: u64,
) -> Result<String> {
    let sk = SigningKey::from_bytes(&p256::FieldBytes::from(*scalar))?;
    let pem = sk.to_pkcs8_pem(LineEnding::LF)?;
    let key = EncodingKey::from_ec_pem(pem.as_bytes())?;
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(issuer.to_string());
    let claims = Claims {
        sub: subject.to_string(),
        iss: issuer.to_string(),
        aud: aud.to_string(),
        iat,
        exp: iat.saturating_add(ttl_secs),
        scope: scope.to_string(),
    };
    Ok(encode(&header, &claims, &key)?)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let token = mint(
        &dev_signing_scalar(),
        &cli.issuer,
        &cli.subject,
        &cli.device,
        &cli.capability,
        now,
        cli.ttl_secs,
    )?;
    println!("{token}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
    use p256::ecdsa::VerifyingKey;
    use p256::pkcs8::EncodePublicKey;

    // A far-future exp so `decode`'s expiry check (against wall-clock now) passes.
    const LONG_TTL: u64 = 99_999_999_999;

    fn decoding_key() -> DecodingKey {
        let sk = SigningKey::from_bytes(&p256::FieldBytes::from(dev_signing_scalar())).unwrap();
        let pem = sk
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        DecodingKey::from_ec_pem(pem.as_bytes()).unwrap()
    }

    /// Replicates `TieredAuthorizer`'s verification: decode ES256 with
    /// set_audience/set_issuer + required claims, then check the capability
    /// scope. A token this minter produces must pass.
    #[test]
    fn minted_token_satisfies_the_authorizer_contract() {
        let token = mint(
            &dev_signing_scalar(),
            "high-consequence-issuer",
            "dev-operator",
            "rig-1",
            "factory-reset",
            1_000,
            LONG_TTL,
        )
        .unwrap();

        let kid = decode_header(&token).unwrap().kid.unwrap();
        assert_eq!(kid, "high-consequence-issuer", "kid must name the issuer");

        let mut v = Validation::new(Algorithm::ES256);
        v.set_audience(&["rig-1"]);
        v.set_issuer(&["high-consequence-issuer"]);
        v.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
        let data =
            decode::<serde_json::Value>(&token, &decoding_key(), &v).expect("token must verify");
        assert_eq!(data.claims["scope"], "factory-reset");
        assert_eq!(data.claims["sub"], "dev-operator");
    }

    /// The device provisions `FACTORY_SIGNING_PUBLIC` into the HC anchor, so the
    /// minter must sign with the matching scalar or on-device verification fails.
    #[test]
    fn dev_key_matches_provisioned_anchor() {
        assert_eq!(dev_signing_scalar(), hsm::payload::FACTORY_SIGNING_SCALAR);
        let sk = SigningKey::from_bytes(&p256::FieldBytes::from(dev_signing_scalar())).unwrap();
        let from_anchor =
            VerifyingKey::from_sec1_bytes(&hsm::payload::FACTORY_SIGNING_PUBLIC).unwrap();
        assert_eq!(
            sk.verifying_key(),
            &from_anchor,
            "minter key must match the provisioned HC anchor"
        );
    }

    /// A mismatched `aud` is rejected — the cross-target replay guard works.
    #[test]
    fn wrong_audience_is_rejected() {
        let token = mint(
            &dev_signing_scalar(),
            "high-consequence-issuer",
            "op",
            "rig-1",
            "factory-reset",
            1_000,
            LONG_TTL,
        )
        .unwrap();
        let mut v = Validation::new(Algorithm::ES256);
        v.set_audience(&["other-rig"]);
        v.set_issuer(&["high-consequence-issuer"]);
        assert!(decode::<serde_json::Value>(&token, &decoding_key(), &v).is_err());
    }
}
