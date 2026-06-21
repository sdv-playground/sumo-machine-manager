//! The **delegated-rights X.509 extension**.
//!
//! In the delegation trust model (`docs/design/authorization.md` §5/§6) the device
//! pins only *roots* (online/Tower + onboard). A delegate — e.g. the workshop
//! minter — is **not** pinned; it presents a cert chained to a pinned root, and the
//! capabilities it is permitted to grant ride in **its own cert** as this extension,
//! signed by the issuing root. Because the root vouches for exactly these scopes, a
//! delegate **cannot self-escalate**: the verifier honours a token's capability only
//! if the signing delegate's cert grants it.
//!
//! Wire form: a non-critical X.509 v3 extension whose value is a DER `UTF8String` of
//! space-delimited capability scopes (same grammar as the JWT `scope` claim), e.g.
//! `"reset:execute update:transfer update:verdict"`. Non-critical so a verifier that
//! predates the extension simply grants nothing extra rather than rejecting the cert.

use const_oid::{AssociatedOid, ObjectIdentifier};
use der::asn1::{OctetString, Utf8StringRef};
use der::{Decode, Encode};
use x509_cert::ext::{AsExtension, Extension};
use x509_cert::name::Name;
use x509_cert::Certificate;

/// OID for the delegated-rights extension.
///
/// **PLACEHOLDER** under a private arc — assign the real TRATON/CSI enterprise arc
/// (`1.3.6.1.4.1.<PEN>…`) before this leaves dev.
pub const DELEGATED_RIGHTS_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1.1");

/// Build the delegated-rights extension carrying `scopes` (space-delimited
/// capability strings). Issued by a root onto a delegate's cert.
pub fn build_extension(scopes: &str) -> der::Result<Extension> {
    let value_der = Utf8StringRef::new(scopes)?.to_der()?;
    Ok(Extension {
        extn_id: DELEGATED_RIGHTS_OID,
        critical: false,
        extn_value: OctetString::new(value_der)?,
    })
}

/// Issuance newtype for the delegated-rights extension, for use with
/// [`x509_cert::builder::CertificateBuilder::add_extension`].
///
/// Holds the space-delimited scope string. Its DER form is a **bare
/// `UTF8String`** (no `SEQUENCE`, no `OCTET STRING` wrapper) — the builder's
/// `AsExtension::to_extension` is what wraps that in the extension's
/// `extn_value` `OCTET STRING`. That makes the on-the-wire bytes identical to
/// [`build_extension`], so [`granted_scopes`] / [`parse_scopes`] read it back
/// unchanged.
pub struct DelegatedRightsExt(pub String);

impl AssociatedOid for DelegatedRightsExt {
    const OID: ObjectIdentifier = DELEGATED_RIGHTS_OID;
}

impl Encode for DelegatedRightsExt {
    fn encoded_len(&self) -> der::Result<der::Length> {
        Utf8StringRef::new(&self.0)?.encoded_len()
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        Utf8StringRef::new(&self.0)?.encode(encoder)
    }
}

impl AsExtension for DelegatedRightsExt {
    fn critical(&self, _subject: &Name, _extensions: &[Extension]) -> bool {
        // Non-critical: a verifier predating the extension grants nothing extra
        // rather than rejecting the cert (see module docs).
        false
    }
}

/// Decode the granted scopes from an extension's DER value (the inner `UTF8String`).
/// `None` when the bytes are not a valid `UTF8String` — never panics on garbage.
pub fn parse_scopes(extn_value_der: &[u8]) -> Option<Vec<String>> {
    let s = Utf8StringRef::from_der(extn_value_der).ok()?;
    Some(s.as_str().split_whitespace().map(str::to_string).collect())
}

/// The scopes a delegate cert is permitted to grant, if it carries the extension.
/// `None` = no delegation present (the delegate grants nothing extra).
pub fn granted_scopes(cert: &Certificate) -> Option<Vec<String>> {
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    let ext = exts.iter().find(|e| e.extn_id == DELEGATED_RIGHTS_OID)?;
    parse_scopes(ext.extn_value.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_value_round_trips() {
        let scopes = "reset:execute update:transfer update:verdict";
        let ext = build_extension(scopes).unwrap();
        assert_eq!(ext.extn_id, DELEGATED_RIGHTS_OID);
        assert!(!ext.critical, "delegated-rights must be non-critical");
        let got = parse_scopes(ext.extn_value.as_bytes()).unwrap();
        assert_eq!(
            got,
            vec!["reset:execute", "update:transfer", "update:verdict"]
        );
    }

    #[test]
    fn empty_delegation_round_trips_to_no_scopes() {
        let ext = build_extension("").unwrap();
        assert!(parse_scopes(ext.extn_value.as_bytes()).unwrap().is_empty());
    }

    #[test]
    fn garbage_value_is_none_never_panics() {
        assert!(parse_scopes(&[0xff, 0x00, 0x13]).is_none());
        assert!(parse_scopes(&[]).is_none());
    }

    /// Issuance↔reading round-trip through a *real* certificate: build a leaf
    /// carrying `DelegatedRightsExt`, then read the scopes back with
    /// `granted_scopes`. Proves the `AsExtension` newtype emits the exact bytes
    /// the reader expects.
    #[test]
    fn ext_newtype_round_trips_through_a_cert() {
        use std::str::FromStr;
        use std::time::Duration;

        use const_oid::db::rfc5280::ID_KP_CLIENT_AUTH;
        use p256::ecdsa::{DerSignature, SigningKey};
        use rand::rngs::OsRng;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::ext::pkix::ExtendedKeyUsage;
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::spki::SubjectPublicKeyInfoOwned;
        use x509_cert::time::Validity;

        let ca_key = SigningKey::random(&mut OsRng);
        let ca_name = Name::from_str("CN=test delegated-rights root").unwrap();
        let leaf_key = SigningKey::random(&mut OsRng);
        let leaf_spki = SubjectPublicKeyInfoOwned::from_key(*leaf_key.verifying_key()).unwrap();

        let mut builder = CertificateBuilder::new(
            Profile::Leaf {
                issuer: ca_name.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::new(&[1]).unwrap(),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            Name::from_str("CN=delegate").unwrap(),
            leaf_spki,
            &ca_key,
        )
        .unwrap();
        builder
            .add_extension(&ExtendedKeyUsage(vec![ID_KP_CLIENT_AUTH]))
            .unwrap();
        builder
            .add_extension(&DelegatedRightsExt(
                "reset:execute update:transfer".to_string(),
            ))
            .unwrap();
        let cert = builder.build::<DerSignature>().unwrap();

        let got = granted_scopes(&cert).expect("cert should carry delegated-rights");
        assert_eq!(got, vec!["reset:execute", "update:transfer"]);
    }
}
