//! Delegate-chain verification for the delegation trust model.
//!
//! A delegate (e.g. the workshop minter) is **not pinned**. It presents a
//! client-cert chain (`x5c`, leaf-first) that must terminate at a *pinned root*,
//! and the capabilities it is permitted to grant ride in the leaf's
//! [`delegated_rights`](crate::sovd::delegated_rights) extension. This module
//! does the trust decision: it hands the chain to the **rustls webpki client
//! verifier**, which performs root pinning + path building + signature checks +
//! validity-window checks against the pinned root. We do *not* hand-roll any of
//! that — a forged, mis-rooted, or expired chain is rejected because
//! `verify_client_cert` rejects it.
//!
//! What this module does *not* do: it never touches a JWT. The caller verifies
//! the token signature itself, against the now-trusted leaf's public key, and
//! intersects the token's requested scopes with [`DelegateAuthority::granted_scopes`].

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use x509_cert::der::Decode;
use x509_cert::Certificate;

use crate::sovd::delegated_rights::granted_scopes;

/// A delegate whose cert chain verified to the pinned root.
///
/// `leaf_der` is the verified leaf — the caller checks the JWT signature against
/// this key. `granted_scopes` is the (possibly empty) capability set the leaf's
/// delegated-rights extension authorises it to grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegateAuthority {
    /// DER of the verified leaf certificate.
    pub leaf_der: Vec<u8>,
    /// Scopes the leaf's delegated-rights extension grants (empty if absent).
    pub granted_scopes: Vec<String>,
}

/// Why a delegate chain was rejected.
#[derive(Debug)]
pub enum DelegationError {
    /// `x5c` was empty — there is no leaf to verify.
    NoChain,
    /// A certificate (the pinned root PEM, or the verified leaf) failed to parse.
    BadCert(String),
    /// The chain did not verify to the pinned root, or is outside its validity
    /// window. This is the root-pinning / path / signature / expiry rejection.
    ChainNotTrusted(String),
}

impl std::fmt::Display for DelegationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DelegationError::NoChain => write!(f, "delegate presented an empty certificate chain"),
            DelegationError::BadCert(e) => write!(f, "certificate did not parse: {e}"),
            DelegationError::ChainNotTrusted(e) => {
                write!(f, "delegate chain did not verify to the pinned root: {e}")
            }
        }
    }
}
impl std::error::Error for DelegationError {}

/// Verify `x5c` (DER certs, leaf-first) chains to `pinned_root_pem`, valid at `now`.
///
/// Returns the leaf DER plus the scopes its delegated-rights extension grants.
/// Does **not** verify any JWT signature — the caller does that with the leaf key.
///
/// The trust decision is entirely the rustls webpki client verifier's: root
/// pinning, path building, signature verification, and the validity window are
/// all enforced by [`WebPkiClientVerifier::verify_client_cert`] against the
/// pinned root, using the explicitly-supplied ring crypto provider (no reliance
/// on a process-default provider being installed).
pub fn verify_delegate_chain(
    x5c: &[Vec<u8>],
    pinned_root_pem: &[u8],
    now: UnixTime,
) -> Result<DelegateAuthority, DelegationError> {
    // 1. Leaf-first split: first cert is the leaf, the rest are intermediates.
    let (leaf_bytes, intermediate_bytes) = x5c.split_first().ok_or(DelegationError::NoChain)?;
    let leaf_der = CertificateDer::from(leaf_bytes.clone());
    let intermediate_ders: Vec<CertificateDer<'_>> = intermediate_bytes
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect();

    // 2. Pinned roots from PEM. An empty/garbage PEM yields no anchors, which
    //    the verifier builder rejects below — nothing can chain to nothing.
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(pinned_root_pem)) {
        let cert = cert.map_err(|e| DelegationError::BadCert(e.to_string()))?;
        roots
            .add(cert)
            .map_err(|e| DelegationError::BadCert(e.to_string()))?;
    }

    // 3. Build the verifier with the ring provider explicitly — we do not depend
    //    on a process-wide default CryptoProvider having been installed.
    let verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .map_err(|e| DelegationError::ChainNotTrusted(e.to_string()))?;

    // 4. THE trust decision: root pinning + path + signatures + validity at `now`.
    //    The verifier requires the leaf to carry the clientAuth EKU.
    verifier
        .verify_client_cert(&leaf_der, &intermediate_ders, now)
        .map_err(|e| DelegationError::ChainNotTrusted(e.to_string()))?;

    // 5. Read the (now-trusted) leaf's delegated rights. Absent extension =>
    //    grants nothing.
    let leaf = Certificate::from_der(leaf_der.as_ref())
        .map_err(|e| DelegationError::BadCert(e.to_string()))?;
    let scopes = granted_scopes(&leaf).unwrap_or_default();

    Ok(DelegateAuthority {
        leaf_der: leaf_der.as_ref().to_vec(),
        granted_scopes: scopes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::time::Duration;

    use const_oid::db::rfc5280::ID_KP_CLIENT_AUTH;
    use p256::ecdsa::{DerSignature, SigningKey};
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

    /// A fixed "now" that sits inside every `Validity::from_now(1h)` window we
    /// build below (certs are minted at test time, so real wall-clock now is in
    /// their window). Used as the verification instant.
    fn now() -> UnixTime {
        UnixTime::now()
    }

    /// Issue a leaf signed by `ca_key`/`ca_name`, with the clientAuth EKU and an
    /// optional delegated-rights extension, over a freshly generated key. Returns
    /// the leaf DER and (for completeness) drops the leaf private key — the chain
    /// test never needs to sign with it.
    fn issue_leaf(
        ca_key: &SigningKey,
        ca_name: &Name,
        cn: &str,
        scopes: Option<&str>,
        validity: Validity,
        serial: u8,
    ) -> Vec<u8> {
        let leaf_key = SigningKey::random(&mut OsRng);
        let spki = SubjectPublicKeyInfoOwned::from_key(*leaf_key.verifying_key()).unwrap();
        let mut builder = CertificateBuilder::new(
            Profile::Leaf {
                issuer: ca_name.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::new(&[serial]).unwrap(),
            validity,
            Name::from_str(&format!("CN={cn}")).unwrap(),
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

    /// PEM of a self-signed root for `ca_key`/`ca_name`.
    fn ca_root_pem(ca_key: &SigningKey, ca_name: &Name) -> Vec<u8> {
        let spki = SubjectPublicKeyInfoOwned::from_key(*ca_key.verifying_key()).unwrap();
        let cert: X509Certificate = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::new(&[1]).unwrap(),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
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

    fn one_hour_from_now() -> Validity {
        Validity::from_now(Duration::from_secs(3600)).unwrap()
    }

    /// A validity window entirely in the past: [now-2h, now-1h].
    fn expired_window() -> Validity {
        let end = std::time::SystemTime::now() - Duration::from_secs(3600);
        let start = end - Duration::from_secs(3600);
        Validity {
            not_before: x509_cert::time::Time::try_from(start).unwrap(),
            not_after: x509_cert::time::Time::try_from(end).unwrap(),
        }
    }

    #[test]
    fn valid_chain_grants_scopes() {
        let ca_key = SigningKey::random(&mut OsRng);
        let ca_name = Name::from_str("CN=root A").unwrap();
        let root_pem = ca_root_pem(&ca_key, &ca_name);

        let leaf = issue_leaf(
            &ca_key,
            &ca_name,
            "delegate",
            Some("reset:execute update:transfer"),
            one_hour_from_now(),
            2,
        );

        let auth = verify_delegate_chain(std::slice::from_ref(&leaf), &root_pem, now())
            .expect("a leaf under the pinned root must verify");
        assert_eq!(auth.leaf_der, leaf);
        assert_eq!(
            auth.granted_scopes,
            vec!["reset:execute", "update:transfer"]
        );
    }

    /// Root pinning: the leaf is issued by CA **A** but we pin root **B**. The
    /// webpki verifier cannot build a path from leaf→B (no signature by B over
    /// the leaf, and A is not in the trust store), so it rejects.
    #[test]
    fn leaf_under_wrong_root_rejected() {
        let ca_a = SigningKey::random(&mut OsRng);
        let name_a = Name::from_str("CN=root A").unwrap();
        let leaf = issue_leaf(
            &ca_a,
            &name_a,
            "delegate",
            Some("reset:execute"),
            one_hour_from_now(),
            2,
        );

        // Pin a DIFFERENT, unrelated CA.
        let ca_b = SigningKey::random(&mut OsRng);
        let name_b = Name::from_str("CN=root B").unwrap();
        let root_b_pem = ca_root_pem(&ca_b, &name_b);

        let err = verify_delegate_chain(&[leaf], &root_b_pem, now())
            .expect_err("a leaf under root A must NOT verify against pinned root B");
        assert!(
            matches!(err, DelegationError::ChainNotTrusted(_)),
            "wrong-root rejection must be ChainNotTrusted, got {err:?}"
        );
    }

    /// Validity-window enforcement: a leaf whose window is entirely in the past
    /// is rejected when verified at the present instant — even though it chains
    /// to the pinned root.
    #[test]
    fn expired_leaf_rejected() {
        let ca_key = SigningKey::random(&mut OsRng);
        let ca_name = Name::from_str("CN=root A").unwrap();
        let root_pem = ca_root_pem(&ca_key, &ca_name);

        let leaf = issue_leaf(
            &ca_key,
            &ca_name,
            "delegate",
            Some("reset:execute"),
            expired_window(),
            2,
        );

        let err = verify_delegate_chain(&[leaf], &root_pem, now())
            .expect_err("an expired leaf must NOT verify at the present instant");
        assert!(
            matches!(err, DelegationError::ChainNotTrusted(_)),
            "expired-leaf rejection must be ChainNotTrusted, got {err:?}"
        );
    }

    #[test]
    fn empty_chain_is_no_chain() {
        let ca_key = SigningKey::random(&mut OsRng);
        let ca_name = Name::from_str("CN=root A").unwrap();
        let root_pem = ca_root_pem(&ca_key, &ca_name);

        let err = verify_delegate_chain(&[], &root_pem, now())
            .expect_err("an empty x5c has no leaf to verify");
        assert!(
            matches!(err, DelegationError::NoChain),
            "empty chain must be NoChain, got {err:?}"
        );
    }

    /// A valid leaf with no delegated-rights extension verifies, but grants
    /// nothing — the delegate can authorise no capability.
    #[test]
    fn valid_leaf_without_extension_grants_nothing() {
        let ca_key = SigningKey::random(&mut OsRng);
        let ca_name = Name::from_str("CN=root A").unwrap();
        let root_pem = ca_root_pem(&ca_key, &ca_name);

        let leaf = issue_leaf(&ca_key, &ca_name, "delegate", None, one_hour_from_now(), 2);

        let auth = verify_delegate_chain(&[leaf], &root_pem, now())
            .expect("a valid leaf must verify even without the extension");
        assert!(
            auth.granted_scopes.is_empty(),
            "a leaf without delegated-rights grants nothing, got {:?}",
            auth.granted_scopes
        );
    }

    /// The real workshop chain shape: pinned OEM root -> workshop-CA intermediate
    /// (SubCA, signed by the root) -> delegate leaf (signed by the intermediate).
    /// `x5c` is `[leaf, intermediate]`; the verifier must build the full path to
    /// the pinned root through the intermediate. This is the case the design
    /// (§6.2) actually deploys, so it must work — not just direct-under-root.
    #[test]
    fn intermediate_ca_chain_verifies_to_pinned_root() {
        let root_key = SigningKey::random(&mut OsRng);
        let root_name = Name::from_str("CN=OEM root").unwrap();
        let root_pem = ca_root_pem(&root_key, &root_name);

        // Workshop-CA intermediate, signed by the root.
        let int_key = SigningKey::random(&mut OsRng);
        let int_name = Name::from_str("CN=workshop CA").unwrap();
        let int_spki = SubjectPublicKeyInfoOwned::from_key(*int_key.verifying_key()).unwrap();
        let int_der = CertificateBuilder::new(
            Profile::SubCA {
                issuer: root_name.clone(),
                path_len_constraint: Some(0),
            },
            SerialNumber::new(&[3]).unwrap(),
            one_hour_from_now(),
            int_name.clone(),
            int_spki,
            &root_key,
        )
        .unwrap()
        .build::<DerSignature>()
        .unwrap()
        .to_der()
        .unwrap();

        // Delegate leaf, signed by the intermediate (issuer = the intermediate).
        let leaf = issue_leaf(
            &int_key,
            &int_name,
            "delegate",
            Some("reset:execute update:transfer"),
            one_hour_from_now(),
            4,
        );

        let auth = verify_delegate_chain(&[leaf.clone(), int_der], &root_pem, now())
            .expect("leaf -> workshop-CA -> pinned root must verify");
        assert_eq!(auth.leaf_der, leaf);
        assert_eq!(
            auth.granted_scopes,
            vec!["reset:execute", "update:transfer"]
        );
    }
}
