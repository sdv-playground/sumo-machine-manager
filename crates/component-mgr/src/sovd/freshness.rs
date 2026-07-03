//! §7.2 master freshness coordinator — the signed `{floor, epoch}` assertion
//! and the monotonic-adoption safety core.
//!
//! HSM-agnostic by design (like [`super::authz`]): signing and verifying are
//! done through caller-supplied closures — the host wires the HSM
//! `FreshnessSigning` key; a peer ECU wires its *pinned* master key — so this
//! module holds no key material and makes no trust decision itself.
//!
//! Scope today is the **producer** side: a master mints + signs + serves the
//! assertion, single-node. The cross-ECU consumer (adopt-from-a-remote-master)
//! and peer-key provisioning are deferred; [`adopt_monotonic`] and
//! [`SignedFreshness::verify`] are the pieces that consumer will reuse.

use serde::{Deserialize, Serialize};

/// Domain-separation tag for the signed bytes. Bump the version suffix if the
/// canonical encoding below ever changes, so an old verifier can never be
/// tricked into accepting a new-format blob (or vice versa). v2: the safe-time
/// floor is now UNIX **seconds** (was ns) — matching the HSM-resident floor's
/// unit (docs/design/safe-time-floor.md).
const DOMAIN_TAG: &[u8] = b"sumo-freshness-v2\0";

/// The vehicle-level freshness statement a master coordinator signs (§7.2):
/// the current monotonic epoch and safe-time-floor, scoped to one vehicle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshnessAssertion {
    /// Scopes the assertion to one vehicle (the §6.4 cross-vehicle replay
    /// guard) — the master's own id (its HSM thumbprint) today; the VIN later.
    pub vehicle_id: String,
    /// Monotonic freshness epoch — bumped at power-on / online-sync. A
    /// vehicle-wide token is fresh only against the current epoch (§7.3).
    pub vehicle_epoch: u64,
    /// Safe-time-floor, **seconds** since the Unix epoch; 0 until a trustworthy
    /// source (the provisioning identity leaf, a signed SUIT timestamp,
    /// Roughtime) lands. Monotonic upper-ratchet, HSM-resident
    /// (docs/design/safe-time-floor.md).
    pub safe_time_floor_seconds: u64,
}

impl FreshnessAssertion {
    /// The exact bytes to sign / verify: the domain tag followed by an
    /// injective encoding (length-prefixed id, then fixed-width little-endian
    /// counters), so no two distinct assertions share a signing preimage.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let id = self.vehicle_id.as_bytes();
        let mut out = Vec::with_capacity(DOMAIN_TAG.len() + 4 + id.len() + 16);
        out.extend_from_slice(DOMAIN_TAG);
        out.extend_from_slice(&(id.len() as u32).to_le_bytes());
        out.extend_from_slice(id);
        out.extend_from_slice(&self.vehicle_epoch.to_le_bytes());
        out.extend_from_slice(&self.safe_time_floor_seconds.to_le_bytes());
        out
    }

    /// Sign with a caller-supplied signer (the host: the HSM `FreshnessSigning`
    /// key) and wrap into the distributable form. `signing_key_der` is the
    /// signer's SPKI public-key DER — see [`SignedFreshness::signing_key_hex`].
    pub fn sign<E>(
        self,
        alg: &str,
        signing_key_der: &[u8],
        sign_fn: impl FnOnce(&[u8]) -> Result<Vec<u8>, E>,
    ) -> Result<SignedFreshness, E> {
        let signature = sign_fn(&self.signing_bytes())?;
        Ok(SignedFreshness {
            assertion: self,
            alg: alg.to_string(),
            signature_hex: hex::encode(signature),
            signing_key_hex: hex::encode(signing_key_der),
        })
    }
}

/// The signed, distributable form — e.g. the `x-sumo-freshness` endpoint body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedFreshness {
    #[serde(flatten)]
    pub assertion: FreshnessAssertion,
    /// Signature algorithm (`"ES256"`).
    pub alg: String,
    /// Hex of the signature over [`FreshnessAssertion::signing_bytes`].
    pub signature_hex: String,
    /// Hex of the signer's SPKI public-key DER. A consumer verifies the
    /// signature against this key — but trust comes from **pinning**: the
    /// consumer MUST compare it to the provisioned master key (§7.2) and never
    /// trust an embedded key on its own.
    pub signing_key_hex: String,
}

impl SignedFreshness {
    /// Verify via a caller-supplied verifier, which decides WHICH key to trust
    /// (and so owns the pinning decision). Returns true iff the signature over
    /// the recomputed signing bytes checks out.
    pub fn verify(&self, verify_fn: impl FnOnce(&[u8], &[u8]) -> bool) -> bool {
        let Ok(sig) = hex::decode(&self.signature_hex) else {
            return false;
        };
        verify_fn(&self.assertion.signing_bytes(), &sig)
    }
}

/// Adopt an incoming monotonic value: take the max, never go backwards.
///
/// The §7.2 safety rule, applied locally to both the epoch and the floor: a
/// compromised or spoofed master can only **stall** freshness (fail to raise
/// it), never **rewind** it — so it can never resurrect an expired grant or
/// replay an old epoch into validity. Same monotonic discipline as the
/// anti-rollback floor in §4/§6.5.
pub fn adopt_monotonic(local: u64, incoming: u64) -> u64 {
    local.max(incoming)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::{Signer, Verifier};
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use p256::pkcs8::{DecodePublicKey, EncodePublicKey};

    /// A deterministic software keypair (fixed scalar) standing in for the HSM
    /// `FreshnessSigning` key — returns (signer, SPKI DER of the public half).
    fn test_signer() -> (SigningKey, Vec<u8>) {
        let sk = SigningKey::from_bytes(&p256::FieldBytes::from([7u8; 32])).unwrap();
        let der = sk
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        (sk, der)
    }

    fn assertion(epoch: u64) -> FreshnessAssertion {
        FreshnessAssertion {
            vehicle_id: "ecu-thumbprint".to_string(),
            vehicle_epoch: epoch,
            safe_time_floor_seconds: 42,
        }
    }

    fn sign_with(sk: &SigningKey, der: &[u8], a: FreshnessAssertion) -> SignedFreshness {
        a.sign("ES256", der, |b| {
            let sig: Signature = sk.sign(b);
            Ok::<_, ()>(sig.to_der().as_bytes().to_vec())
        })
        .unwrap()
    }

    fn verifier_for(signed: &SignedFreshness) -> impl Fn(&[u8], &[u8]) -> bool {
        let vk = VerifyingKey::from_public_key_der(&hex::decode(&signed.signing_key_hex).unwrap())
            .unwrap();
        move |bytes: &[u8], sig: &[u8]| {
            Signature::from_der(sig)
                .map(|s| vk.verify(bytes, &s).is_ok())
                .unwrap_or(false)
        }
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let (sk, der) = test_signer();
        let signed = sign_with(&sk, &der, assertion(5));
        assert!(signed.verify(verifier_for(&signed)));
    }

    #[test]
    fn tampering_with_any_field_breaks_the_signature() {
        let (sk, der) = test_signer();
        let signed = sign_with(&sk, &der, assertion(5));
        let verify = verifier_for(&signed);

        let tampers: [fn(&mut SignedFreshness); 3] = [
            |s| s.assertion.vehicle_epoch += 1,
            |s| s.assertion.safe_time_floor_seconds += 1,
            |s| s.assertion.vehicle_id.push('x'),
        ];
        for tamper in tampers {
            let mut t = signed.clone();
            tamper(&mut t);
            assert!(
                !t.verify(&verify),
                "a tampered field must fail verification"
            );
        }
    }

    #[test]
    fn signing_bytes_are_domain_tagged_and_injective() {
        assert!(assertion(1).signing_bytes().starts_with(DOMAIN_TAG));
        // Different epoch → different preimage.
        assert_ne!(assertion(1).signing_bytes(), assertion(2).signing_bytes());
        // The length-prefix stops id/epoch run-together collisions.
        let a = FreshnessAssertion {
            vehicle_id: "a".into(),
            vehicle_epoch: 0,
            safe_time_floor_seconds: 0,
        };
        let b = FreshnessAssertion {
            vehicle_id: "ab".into(),
            vehicle_epoch: 0,
            safe_time_floor_seconds: 0,
        };
        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn wire_form_is_flat_json() {
        let (sk, der) = test_signer();
        let signed = sign_with(&sk, &der, assertion(3));
        let v: serde_json::Value = serde_json::to_value(&signed).unwrap();
        // `#[serde(flatten)]` hoists the assertion fields to the top level.
        assert_eq!(v["vehicle_epoch"], 3);
        assert_eq!(v["vehicle_id"], "ecu-thumbprint");
        assert_eq!(v["alg"], "ES256");
        assert!(!v["signature_hex"].as_str().unwrap().is_empty());
    }

    #[test]
    fn adopt_monotonic_never_rewinds() {
        assert_eq!(adopt_monotonic(5, 9), 9); // raise forward
        assert_eq!(adopt_monotonic(9, 5), 9); // a lower incoming cannot rewind
        assert_eq!(adopt_monotonic(7, 7), 7); // equal stays
    }
}
