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

use const_oid::ObjectIdentifier;
use der::asn1::{OctetString, Utf8StringRef};
use der::{Decode, Encode};
use x509_cert::ext::Extension;
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
}
