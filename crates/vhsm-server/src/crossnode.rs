//! Cross-node vHSM access over mutually-authenticated TLS.
//!
//! The guest path authenticates a *VM* (source IP + an in-band CWT handshake on
//! the private bridge). A cross-node caller is different: it's another node's
//! host service reaching this vHSM over the in-vehicle network. There the
//! principal is the TLS **client certificate** — a leaf the local
//! `identity-root` trust anchor vouches for (see [`crate::tls`]) — and the cert
//! subject CN is the node id that IAM authorises per-op.
//!
//! There is no in-band handshake here: rustls has already verified the peer's
//! chain before a single byte of vHSM protocol flows, so `serve_crossnode_*`
//! starts straight at op dispatch with the principal already bound. That is the
//! "no random component makes cross-node calls" guarantee — a caller cannot get
//! a serving stream without presenting a cert this node's identity root trusts,
//! and every op it then issues is gated by IAM keyed on that cert's node id.

use std::io::{Read, Write};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use hsm::HsmCryptoProvider;
use secstore::{FileBackend, LinuxSimEncryptor, Secstore};
use sha2::{Digest, Sha256};
use x509_cert::der::Decode;
use x509_cert::Certificate;

use crate::audit::AuditLogger;
use crate::codec;
use crate::handle_table::HandleTable;
use crate::handler::CallerId;
use crate::iam::IamPolicy;
use crate::serve::{dispatch_request, Dispatch};

/// A cross-node caller's verified identity, derived from its TLS client
/// certificate after rustls validated the chain to `identity-root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossNodePrincipal {
    /// Subject CommonName of the client leaf — the node id IAM matches on.
    pub node_id: String,
    /// SHA-256 of the client leaf DER, recorded in the audit log.
    pub cert_thumbprint: [u8; 32],
}

/// Why a client cert couldn't be turned into a principal.
#[derive(Debug)]
pub enum CrossNodeError {
    /// The DER didn't parse as an X.509 certificate.
    BadCertificate(String),
    /// The subject carries no CommonName to use as a node id.
    NoCommonName,
}

impl std::fmt::Display for CrossNodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CrossNodeError::BadCertificate(e) => write!(f, "client certificate did not parse: {e}"),
            CrossNodeError::NoCommonName => {
                write!(f, "client certificate subject has no CommonName")
            }
        }
    }
}
impl std::error::Error for CrossNodeError {}

/// Derive the cross-node principal from a verified client leaf certificate
/// (DER). rustls MUST already have verified the chain to the identity root —
/// this only reads the now-trusted subject CN and computes a thumbprint; it
/// makes no trust decision of its own.
pub fn principal_from_client_cert(cert_der: &[u8]) -> Result<CrossNodePrincipal, CrossNodeError> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| CrossNodeError::BadCertificate(e.to_string()))?;

    // Walk the subject RDNs for the CommonName. `Any::value()` is the raw
    // content octets — the same ASCII text whether the CA encoded the CN as
    // Utf8String or PrintableString, so we needn't branch on the DER tag.
    let node_id = cert
        .tbs_certificate
        .subject
        .0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .find(|atv| atv.oid == const_oid::db::rfc4519::COMMON_NAME)
        .and_then(|atv| std::str::from_utf8(atv.value.value()).ok())
        .map(|s| s.to_string())
        .ok_or(CrossNodeError::NoCommonName)?;

    let cert_thumbprint: [u8; 32] = Sha256::digest(cert_der).into();
    Ok(CrossNodePrincipal {
        node_id,
        cert_thumbprint,
    })
}

/// Serve a cross-node caller over an already-established, mutually-authenticated
/// stream. `principal` was derived from the peer's verified client cert;
/// `peer_ip` is a diagnostic only (not security-relevant). Runs the shared
/// op-dispatch loop until the peer hangs up, then releases any dynamic handles
/// the node minted on this connection.
#[allow(clippy::too_many_arguments)]
pub fn serve_crossnode_connection<S: Read + Write>(
    stream: &mut S,
    principal: &CrossNodePrincipal,
    peer_ip: IpAddr,
    handle_table: &Arc<Mutex<HandleTable>>,
    iam: &IamPolicy,
    crypto: &dyn HsmCryptoProvider,
    store: Option<&Secstore<LinuxSimEncryptor, FileBackend>>,
    audit: &Arc<Mutex<AuditLogger>>,
) {
    let caller = CallerId {
        peer_ip,
        vm_id: principal.node_id.clone(),
        cert_thumbprint: principal.cert_thumbprint,
    };
    tracing::info!(
        node = %caller.vm_id,
        peer = %peer_ip,
        "cross-node mTLS connection authenticated; serving"
    );

    loop {
        let req = match codec::read_request(stream) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                tracing::debug!(node = %caller.vm_id, error = %e, "cross-node read closed");
                break;
            }
        };
        match dispatch_request(
            &req,
            &caller,
            stream,
            handle_table,
            iam,
            crypto,
            store,
            audit,
        ) {
            Dispatch::Continue => {}
            Dispatch::Close => break,
        }
    }

    handle_table.lock().unwrap().remove_by_vm_id(&caller.vm_id);
    tracing::info!(node = %caller.vm_id, "cross-node connection closed, dynamic handles released");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::str::FromStr;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use const_oid::db::rfc5280::{ID_KP_CLIENT_AUTH, ID_KP_SERVER_AUTH};
    use hsm::{HsmCryptoProvider, KeyRole};
    use hsm_sim_backend::SimHsm;
    use p256::ecdsa::{DerSignature, SigningKey};
    use rand::rngs::OsRng;
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConnection, StreamOwned};
    use vhsm_proto::codec::{read_response, write_request};
    use vhsm_proto::{
        Op, Request, Response, StatusCode, ALG_ECC_P256, HANDLE_SW_AUTHORITY, PERM_GET_PUBKEY,
        PERM_SIGN, PERM_VERIFY,
    };
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::der::asn1::Ia5String;
    use x509_cert::der::{Decode, Encode, EncodePem};
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::{ExtendedKeyUsage, SubjectAltName};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;
    use x509_cert::time::Validity;
    use x509_cert::Certificate as X509Certificate;

    use crate::audit::AuditLogger;
    use crate::handle_table::HandleTable;
    use crate::iam::IamPolicy;
    use crate::tls::{identity_root_store, server_config};

    // Cert-building helpers — the same shapes as the tls.rs tests (a CA, leaves
    // with the right EKU). Duplicated rather than shared because Rust test
    // modules are file-private; kept minimal.
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

    fn trust_from_pem(root_pem: &[u8]) -> RootCertStore {
        let mut trust = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(root_pem)) {
            trust.add(cert.unwrap()).unwrap();
        }
        trust
    }

    /// Stand up a real cross-node exchange: a live TCP listener whose server
    /// identity is an HSM `TlsIdentity` key, an HSM-backed mTLS client whose
    /// leaf CN is `client_cn`, and one `Sign` against well-known handle
    /// `sw-authority`. Returns the node id the *server* derived from the
    /// client's verified cert, plus the `Response` the client received — so a
    /// caller can assert both the principal derivation and the IAM outcome.
    fn run_cross_node_sign(policy_yaml: &str, client_cn: &str, msg: &[u8]) -> (String, Response) {
        let ca_key = SigningKey::random(&mut OsRng);
        let ca_name = Name::from_str("CN=test identity root").unwrap();
        let root_pem = ca_root_pem(&ca_key, &ca_name);

        // --- Server node ("node-b"): HSM holds the TLS identity key AND the EC
        // signer that handle sw-authority points at.
        let server_dir = tempfile::tempdir().unwrap();
        let server_hsm = SimHsm::new(server_dir.path().to_path_buf());
        let tls_kid = KeyRole::TlsIdentity.handle();
        let server_spki = server_hsm.generate_key(tls_kid, ALG_ECC_P256).unwrap();
        // The signer behind handle sw-authority. The well-known handle resolves
        // to key_id "sw-authority", which is the name the policy authorises.
        server_hsm
            .generate_key(KeyRole::SoftwareAuthority.handle(), ALG_ECC_P256)
            .unwrap();
        let server_leaf = issue_leaf(
            &ca_key,
            &ca_name,
            "node-b",
            &server_spki,
            ID_KP_SERVER_AUTH,
            Some("localhost"),
            2,
        );
        let server_hsm: Arc<dyn HsmCryptoProvider> = Arc::new(server_hsm);

        let client_roots = identity_root_store(&root_pem).unwrap();
        let server_cfg = Arc::new(
            server_config(server_hsm.clone(), tls_kid, vec![server_leaf], client_roots).unwrap(),
        );

        let iam = IamPolicy::parse(policy_yaml).unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel::<String>();

        let server = thread::spawn(move || {
            let (mut tcp, peer) = listener.accept().unwrap();
            let mut conn = ServerConnection::new(server_cfg).unwrap();
            // Drive the mTLS handshake to completion, then derive the principal
            // from the now-verified client leaf BEFORE serving a single op.
            conn.complete_io(&mut tcp).unwrap();
            let peer_certs = conn
                .peer_certificates()
                .expect("client presented no cert")
                .to_vec();
            let principal = principal_from_client_cert(peer_certs[0].as_ref()).unwrap();
            tx.send(principal.node_id.clone()).unwrap();

            let mut table = HandleTable::new();
            table.register_well_known(
                HANDLE_SW_AUTHORITY,
                "sw-authority",
                ALG_ECC_P256,
                PERM_SIGN | PERM_VERIFY | PERM_GET_PUBKEY,
            );
            let table = Arc::new(Mutex::new(table));
            let audit = Arc::new(Mutex::new(AuditLogger::disabled()));

            let mut tls = StreamOwned::new(conn, tcp);
            serve_crossnode_connection(
                &mut tls,
                &principal,
                peer.ip(),
                &table,
                &iam,
                &*server_hsm,
                None,
                &audit,
            );
        });

        // --- Client node ("node-a" / client_cn): HSM-backed client identity.
        let client_dir = tempfile::tempdir().unwrap();
        let client_hsm = SimHsm::new(client_dir.path().to_path_buf());
        let client_kid = KeyRole::TlsIdentity.handle();
        let client_spki = client_hsm.generate_key(client_kid, ALG_ECC_P256).unwrap();
        let client_leaf = issue_leaf(
            &ca_key,
            &ca_name,
            client_cn,
            &client_spki,
            ID_KP_CLIENT_AUTH,
            None,
            3,
        );
        let client_hsm = Arc::new(client_hsm);
        let sign_hsm = client_hsm.clone();
        let sign_fn = move |m: &[u8]| {
            HsmCryptoProvider::sign(&*sign_hsm, client_kid, m).map_err(|e| e.to_string())
        };
        let certified = hsm_rustls::hsm_certified_key(vec![client_leaf], sign_fn);
        let resolver = Arc::new(hsm_rustls::HsmClientIdentity::new(certified));
        let client_cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(trust_from_pem(&root_pem))
                .with_client_cert_resolver(resolver),
        );

        let tcp = TcpStream::connect(addr).unwrap();
        let client_conn =
            ClientConnection::new(client_cfg, ServerName::try_from("localhost").unwrap()).unwrap();
        let mut tls = StreamOwned::new(client_conn, tcp);

        let mut payload = HANDLE_SW_AUTHORITY.to_le_bytes().to_vec();
        payload.extend_from_slice(msg);
        let req = Request {
            op: Op::Sign as u32,
            session_id: 1,
            payload,
        };
        write_request(&mut tls, &req).unwrap();
        let resp = read_response(&mut tls).unwrap();
        drop(tls); // hang up so the server's serve loop ends

        let node_id = rx.recv().unwrap();
        server.join().unwrap();
        (node_id, resp)
    }

    /// CN extraction + thumbprint from a real leaf — the cheap unit, isolated
    /// from the TLS machinery.
    #[test]
    fn principal_is_derived_from_cert_cn() {
        let ca_key = SigningKey::random(&mut OsRng);
        let ca_name = Name::from_str("CN=test identity root").unwrap();
        let leaf_key = SigningKey::random(&mut OsRng);
        let leaf_spki = SubjectPublicKeyInfoOwned::from_key(*leaf_key.verifying_key())
            .unwrap()
            .to_der()
            .unwrap();
        let leaf = issue_leaf(
            &ca_key,
            &ca_name,
            "node-7",
            &leaf_spki,
            ID_KP_CLIENT_AUTH,
            None,
            7,
        );

        let p = principal_from_client_cert(leaf.as_ref()).unwrap();
        assert_eq!(p.node_id, "node-7");
        // Thumbprint is SHA-256 of the exact DER we parsed.
        let expect: [u8; 32] = Sha256::digest(leaf.as_ref()).into();
        assert_eq!(p.cert_thumbprint, expect);
    }

    #[test]
    fn cross_node_sign_succeeds_when_iam_allows_the_node() {
        // Policy authorises node-a on the sw-authority handle for sign+verify.
        let policy = "version: 1\nstatements:\n  - principals: [node-a]\n    handles: [sw-authority]\n    ops: [sign, verify]\n";
        let msg = b"cross-node attestation challenge";
        let (node_id, resp) = run_cross_node_sign(policy, "node-a", msg);

        // The server derived the principal from the live mTLS client cert.
        assert_eq!(node_id, "node-a");
        // The op was authorised and the daemon signed.
        assert_eq!(
            resp.status,
            StatusCode::Ok as u32,
            "expected OK, got status {:#x}",
            resp.status
        );
        assert!(!resp.payload.is_empty(), "signature must be non-empty");
    }

    #[test]
    fn cross_node_sign_is_denied_when_iam_omits_the_node() {
        // Same handle/op, but the policy only names a DIFFERENT node — node-a is
        // authenticated by mTLS yet not authorised, so IAM rejects per-node.
        let policy = "version: 1\nstatements:\n  - principals: [some-other-node]\n    handles: [sw-authority]\n    ops: [sign]\n";
        let (node_id, resp) = run_cross_node_sign(policy, "node-a", b"challenge");

        assert_eq!(node_id, "node-a", "principal still derived from the cert");
        assert_eq!(
            resp.status,
            StatusCode::PolicyReject as u32,
            "an unlisted node must be denied (got {:#x})",
            resp.status
        );
    }
}
