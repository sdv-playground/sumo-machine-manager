//! Cross-node mTLS transport for vhsm-ssd.
//!
//! When a node reaches another node's vHSM over the in-vehicle network (not the
//! local private bridge), the connection is mutually authenticated by **device
//! identity certificate**: this host presents its HSM-backed `TlsIdentity` leaf,
//! and verifies the peer's client leaf against the fleet **identity root** loaded
//! from the policy partition (`roots/`, delivered + signed via OTA — the trust
//! anchor never comes over the vHSM connection itself). The HSM signs the
//! handshake; the private key never leaves it (see the `hsm-rustls` seam).
//!
//! mTLS sits *under* the existing v3 CWT handshake: TLS authenticates *which
//! node*, the CWT authenticates *which principal*. The local guest path (raw TCP
//! and CWT on the private bridge) is untouched — this is the cross-node listener
//! only, and it is off unless configured.

use std::sync::Arc;

use hsm::HsmCryptoProvider;
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Parse PEM trust-anchor bytes (the identity root, e.g. the policy partition's
/// `device-identity-root.pem`) into a `RootCertStore` for verifying peer client
/// certs.
pub fn identity_root_store(pem: &[u8]) -> Result<RootCertStore, BoxError> {
    // One implementation, shared with the cross-node client connector.
    hsm_rustls::roots_from_pem(pem)
}

/// Build the cross-node mTLS `ServerConfig`: present `server_chain` (this host's
/// `TlsIdentity` leaf, leaf first), signing the handshake with the HSM
/// `tls_key_id` key; require + verify the peer's client cert against
/// `client_roots` (the identity root). `crypto` is the daemon's HSM provider —
/// the private key never leaves it.
pub fn server_config(
    crypto: Arc<dyn HsmCryptoProvider>,
    tls_handle: hsm::KeyHandle,
    server_chain: Vec<CertificateDer<'static>>,
    client_roots: RootCertStore,
) -> Result<ServerConfig, BoxError> {
    // Idempotent — first caller installs the ring provider, the rest no-op.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // ECDSA-P256/SHA-256 DER over the message — rustls hands the signer the
    // CertificateVerify message (not a digest), so the HSM's ordinary `sign` is
    // exactly the primitive (no pre-hash). See hsm-rustls.
    let sign_fn = move |msg: &[u8]| crypto.sign(tls_handle, msg).map_err(|e| e.to_string());
    let certified = hsm_rustls::hsm_certified_key(server_chain, sign_fn);
    let resolver = Arc::new(hsm_rustls::HsmServerIdentity::new(certified));

    let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .map_err(|e| format!("build client-cert verifier: {e}"))?;

    Ok(ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(resolver))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::time::Duration;

    use const_oid::db::rfc5280::{ID_KP_CLIENT_AUTH, ID_KP_SERVER_AUTH};
    use hsm_sim_backend::SimHsm;
    use hsm::KeyRole;
    use p256::ecdsa::{DerSignature, SigningKey};
    use p256::pkcs8::EncodePrivateKey;
    use rand::rngs::OsRng;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, ClientConnection, ServerConnection};
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::der::asn1::Ia5String;
    use x509_cert::der::{Decode, Encode, EncodePem};
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::{ExtendedKeyUsage, SubjectAltName};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;
    use x509_cert::time::Validity;
    use x509_cert::Certificate;

    const ALG_ECC_P256: u32 = 0x0021;

    fn issue_leaf(
        ca_key: &SigningKey,
        ca_name: &Name,
        cn: &str,
        subject_spki_der: &[u8],
        eku: const_oid::ObjectIdentifier,
        dns_san: Option<&str>,
        serial: u8,
    ) -> CertificateDer<'static> {
        let spki = SubjectPublicKeyInfoOwned::from_der(subject_spki_der).unwrap();
        let mut builder = CertificateBuilder::new(
            Profile::Leaf {
                issuer: ca_name.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::new(&[serial]).unwrap(),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            Name::from_str(&format!("CN={cn}")).unwrap(),
            spki,
            ca_key,
        )
        .unwrap();
        builder.add_extension(&ExtendedKeyUsage(vec![eku])).unwrap();
        if let Some(dns) = dns_san {
            builder
                .add_extension(&SubjectAltName(vec![GeneralName::DnsName(
                    Ia5String::try_from(dns.to_string()).unwrap(),
                )]))
                .unwrap();
        }
        CertificateDer::from(builder.build::<DerSignature>().unwrap().to_der().unwrap())
    }

    fn ca_root_pem(ca_key: &SigningKey, ca_name: &Name) -> Vec<u8> {
        let spki = SubjectPublicKeyInfoOwned::from_key(*ca_key.verifying_key()).unwrap();
        let cert: Certificate = CertificateBuilder::new(
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

    fn spki(vk: &p256::ecdsa::VerifyingKey) -> Vec<u8> {
        SubjectPublicKeyInfoOwned::from_key(*vk)
            .unwrap()
            .to_der()
            .unwrap()
    }

    fn pump(client: &mut ClientConnection, server: &mut ServerConnection) {
        for _ in 0..16 {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                let mut rd: &[u8] = &buf;
                while !rd.is_empty() {
                    server.read_tls(&mut rd).unwrap();
                }
                server
                    .process_new_packets()
                    .expect("server rejected handshake");
            }
            let mut buf = Vec::new();
            server.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                let mut rd: &[u8] = &buf;
                while !rd.is_empty() {
                    client.read_tls(&mut rd).unwrap();
                }
                client
                    .process_new_packets()
                    .expect("client rejected handshake");
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                return;
            }
        }
        panic!("mTLS handshake did not complete");
    }

    /// The cross-node server, with its TLS key in the HSM, completes mTLS against
    /// a peer client — and verifies the peer's leaf against the identity root
    /// loaded from PEM (the policy-partition path). Proves `server_config` end to
    /// end: HSM-backed server cert + client-cert verification.
    #[test]
    fn hsm_server_completes_mtls_with_verified_client() {
        let ca_key = SigningKey::random(&mut OsRng);
        let ca_name = Name::from_str("CN=test identity root").unwrap();

        // Server: the HSM `TlsIdentity` key + a CA-signed serverAuth leaf (SAN).
        let dir = tempfile::tempdir().unwrap();
        let hsm = SimHsm::new(dir.path().to_path_buf());
        let kid = KeyRole::TlsIdentity.handle();
        let server_spki = hsm.generate_key(kid, ALG_ECC_P256).unwrap();
        let server_leaf = issue_leaf(
            &ca_key,
            &ca_name,
            "node-b",
            &server_spki,
            ID_KP_SERVER_AUTH,
            Some("localhost"),
            2,
        );
        let crypto: Arc<dyn HsmCryptoProvider> = Arc::new(hsm);

        // Verify the peer client against the identity root, loaded from PEM
        // exactly as it would be from the policy partition.
        let root_pem = ca_root_pem(&ca_key, &ca_name);
        let client_roots = identity_root_store(&root_pem).unwrap();
        let server_cfg = server_config(crypto, kid, vec![server_leaf], client_roots).unwrap();

        // Peer client: a (software) key + a CA-signed clientAuth leaf.
        let client_key = SigningKey::random(&mut OsRng);
        let client_leaf = issue_leaf(
            &ca_key,
            &ca_name,
            "node-a",
            &spki(client_key.verifying_key()),
            ID_KP_CLIENT_AUTH,
            None,
            3,
        );
        let client_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            client_key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
        ));
        let mut trust = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(&root_pem[..])) {
            trust.add(cert.unwrap()).unwrap();
        }
        let client_cfg = ClientConfig::builder()
            .with_root_certificates(trust)
            .with_client_auth_cert(vec![client_leaf.clone()], client_key_der)
            .unwrap();

        let mut server = ServerConnection::new(Arc::new(server_cfg)).unwrap();
        let mut client = ClientConnection::new(
            Arc::new(client_cfg),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();

        pump(&mut client, &mut server);

        let peer = server
            .peer_certificates()
            .expect("server got no client cert");
        assert_eq!(
            peer[0], client_leaf,
            "server verified the peer's client leaf"
        );
    }
}
