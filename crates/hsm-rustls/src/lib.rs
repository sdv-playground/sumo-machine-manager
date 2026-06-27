//! An HSM-backed rustls client identity: a [`rustls::sign::SigningKey`] whose
//! private key never leaves the HSM. The ECDSA-P256/SHA-256 signature (DER) is
//! performed by a caller-supplied `sign_fn` — supernova wires the HSM
//! `TlsIdentity` key; the seam itself is HSM-agnostic (just a sign closure),
//! mirroring `component_mgr::sovd::freshness`.
//!
//! On the hashing: rustls hands [`Signer::sign`] the **message** to be signed
//! (the CertificateVerify transcript), and a signer hashes it per its scheme —
//! so `sign_fn` is the ordinary message-signing HSM op (`HsmCryptoProvider::sign`
//! = SHA-256 + DER), **not** a pre-hash. The loopback test in this crate proves
//! a server accepts the resulting client-auth signature.

use std::fmt;
use std::sync::Arc;

use rustls::client::ResolvesClientCert;
use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{RootCertStore, SignatureAlgorithm, SignatureScheme};

/// Signs `message` with the device's mTLS private key — ECDSA-P256 over
/// SHA-256(message), DER-encoded. The private key stays in the HSM; only this
/// closure crosses into the TLS stack.
pub type SignFn = Arc<dyn Fn(&[u8]) -> Result<Vec<u8>, String> + Send + Sync>;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Parse PEM CA certificate(s) into a [`RootCertStore`] — the trust anchor a
/// cross-node mTLS peer (server OR client) cert must chain to, typically the
/// fleet identity root delivered on the policy partition. Errors on a PEM that
/// decodes to no certificates, so a misconfigured anchor fails loud rather than
/// trusting nothing.
pub fn roots_from_pem(pem: &[u8]) -> Result<RootCertStore, BoxError> {
    let mut reader = std::io::BufReader::new(pem);
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut reader) {
        let cert = cert.map_err(|e| format!("parse root PEM: {e}"))?;
        roots.add(cert).map_err(|e| format!("add root: {e}"))?;
    }
    if roots.is_empty() {
        return Err("root PEM contained no certificates".into());
    }
    Ok(roots)
}

struct HsmSigningKey {
    sign_fn: SignFn,
}

impl fmt::Debug for HsmSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HsmSigningKey(ecdsa-p256)")
    }
}

impl SigningKey for HsmSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| {
                Box::new(HsmSigner {
                    sign_fn: self.sign_fn.clone(),
                }) as Box<dyn Signer>
            })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

struct HsmSigner {
    sign_fn: SignFn,
}

impl fmt::Debug for HsmSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HsmSigner(ecdsa-p256-sha256)")
    }
}

impl Signer for HsmSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        (self.sign_fn)(message)
            .map_err(|e| rustls::Error::General(format!("HSM TLS sign failed: {e}")))
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

/// Bundle the device's leaf chain (DER, leaf first) with an HSM-backed signer
/// into a rustls [`CertifiedKey`]. `sign_fn` performs the client-auth signature.
pub fn hsm_certified_key(
    cert_chain: Vec<CertificateDer<'static>>,
    sign_fn: impl Fn(&[u8]) -> Result<Vec<u8>, String> + Send + Sync + 'static,
) -> Arc<CertifiedKey> {
    Arc::new(CertifiedKey::new(
        cert_chain,
        Arc::new(HsmSigningKey {
            sign_fn: Arc::new(sign_fn),
        }),
    ))
}

/// A [`ResolvesClientCert`] that always presents one HSM-backed identity. Wire
/// it into `ClientConfig::builder()...with_client_cert_resolver(Arc::new(_))`.
#[derive(Debug)]
pub struct HsmClientIdentity {
    certified: Arc<CertifiedKey>,
}

impl HsmClientIdentity {
    pub fn new(certified: Arc<CertifiedKey>) -> Self {
        Self { certified }
    }
}

impl ResolvesClientCert for HsmClientIdentity {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        sigschemes
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| self.certified.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// A [`ResolvesServerCert`] that always presents one HSM-backed identity — wire
/// it into `ServerConfig::builder()...with_cert_resolver(Arc::new(_))` to serve
/// (m)TLS with the private key staying in the HSM. Same `CertifiedKey` shape as
/// the client side; a node uses one HSM `TlsIdentity` leaf for both directions.
#[derive(Debug)]
pub struct HsmServerIdentity {
    certified: Arc<CertifiedKey>,
}

impl HsmServerIdentity {
    pub fn new(certified: Arc<CertifiedKey>) -> Self {
        Self { certified }
    }
}

impl ResolvesServerCert for HsmServerIdentity {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.certified.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::time::Duration;

    use const_oid::db::rfc5280::{ID_KP_CLIENT_AUTH, ID_KP_SERVER_AUTH};
    use hsm_sim_backend::SimHsm;
    use hsm::{HsmCryptoProvider, KeyRole};
    use p256::ecdsa::{DerSignature, SigningKey};
    use p256::pkcs8::EncodePrivateKey;
    use rand::rngs::OsRng;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::server::WebPkiClientVerifier;
    use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::der::asn1::Ia5String;
    use x509_cert::der::{Decode, Encode};
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::{ExtendedKeyUsage, SubjectAltName};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;
    use x509_cert::time::Validity;

    const ALG_ECC_P256: u32 = 0x0021;

    /// A self-signed test CA (stands in for the fleet identity root).
    fn test_ca() -> (SigningKey, Name) {
        let key = SigningKey::random(&mut OsRng);
        let name = Name::from_str("CN=test identity root").unwrap();
        (key, name)
    }

    /// Issue a leaf for `subject_spki` (DER), signed by the CA, carrying `eku`
    /// and (for the server) an optional DNS SAN.
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
        let cert = builder.build::<DerSignature>().unwrap();
        CertificateDer::from(cert.to_der().unwrap())
    }

    fn spki_der(vk: &p256::ecdsa::VerifyingKey) -> Vec<u8> {
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

    /// The whole point: a TLS server that requires client auth accepts a client
    /// whose private key lives in the HSM — the HSM signs the CertificateVerify,
    /// the server verifies it against the client leaf. Proves the rustls↔HSM seam
    /// end to end (and that `HsmCryptoProvider::sign` is the right primitive — no
    /// pre-hash).
    #[test]
    fn hsm_backed_client_completes_mtls_handshake() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let (ca_key, ca_name) = test_ca();

        // Server identity: a software key + a CA-signed serverAuth leaf (SAN).
        let server_key = SigningKey::random(&mut OsRng);
        let server_leaf = issue_leaf(
            &ca_key,
            &ca_name,
            "test-server",
            &spki_der(server_key.verifying_key()),
            ID_KP_SERVER_AUTH,
            Some("localhost"),
            2,
        );
        let server_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            server_key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
        ));

        // Client identity: the HSM `TlsIdentity` key + a CA-signed clientAuth leaf.
        let dir = tempfile::tempdir().unwrap();
        let hsm = SimHsm::new(dir.path().to_path_buf());
        let kid = KeyRole::TlsIdentity.handle();
        hsm.generate_key(kid, ALG_ECC_P256).unwrap();
        let client_leaf = issue_leaf(
            &ca_key,
            &ca_name,
            "node-7",
            &hsm.get_public_key_der(kid).unwrap(),
            ID_KP_CLIENT_AUTH,
            None,
            3,
        );

        // Trust root (the CA) for both directions.
        let ca_der = {
            // self-sign the CA root so it can sit in a RootCertStore.
            let spki = SubjectPublicKeyInfoOwned::from_key(*ca_key.verifying_key()).unwrap();
            let cert = CertificateBuilder::new(
                Profile::Root,
                SerialNumber::new(&[1]).unwrap(),
                Validity::from_now(Duration::from_secs(3600)).unwrap(),
                ca_name.clone(),
                spki,
                &ca_key,
            )
            .unwrap()
            .build::<DerSignature>()
            .unwrap();
            CertificateDer::from(cert.to_der().unwrap())
        };
        let mut roots = RootCertStore::empty();
        roots.add(ca_der).unwrap();

        // Server: require client auth against the CA.
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots.clone()))
            .build()
            .unwrap();
        let server_config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![server_leaf], server_key_der)
            .unwrap();

        // Client: HSM-backed identity; the HSM signs the handshake.
        let sign_fn =
            move |msg: &[u8]| HsmCryptoProvider::sign(&hsm, kid, msg).map_err(|e| e.to_string());
        let identity =
            HsmClientIdentity::new(hsm_certified_key(vec![client_leaf.clone()], sign_fn));
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_cert_resolver(Arc::new(identity));

        let mut client = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        pump(&mut client, &mut server);

        // The server saw + accepted the HSM-backed client certificate.
        let peer = server
            .peer_certificates()
            .expect("server got no client cert");
        assert_eq!(peer[0], client_leaf, "server's client cert is the HSM leaf");
    }
}
