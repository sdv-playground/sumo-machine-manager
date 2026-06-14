//! Cross-node vHSM client connector.
//!
//! The piece that lets a host service on one node REACH another node's vHSM: it
//! dials the peer's `--cross-node-listen` bind over mutually-authenticated TLS —
//! presenting this node's HSM-backed `TlsIdentity` leaf (the private key never
//! leaves the HSM, via [`hsm_rustls`]) and verifying the peer against the fleet
//! identity root — and hands back a ready [`vhsm_client::VhsmClient`].
//!
//! This is the client counterpart to `vhsm-ssd`'s cross-node listener, kept as a
//! SEPARATE crate from `vhsm-client` (the transport-agnostic op codec) so that
//! codec stays free of TLS/HSM deps for `guest-vm-sdk`; this crate adds the
//! HSM-backed mTLS transport on top.
//!
//! Identity is the certificate — there is no in-band CWT. A caller can only
//! reach a peer by presenting a leaf the peer's identity root trusts, and the
//! peer then authorizes every op via its IAM keyed on this node's cert CN. The
//! private key stays in the HSM; this crate only supplies the `sign_fn` that
//! asks the HSM to sign the handshake.

use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use vhsm_client::VhsmClient;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The mTLS stream a [`connect`] call yields a [`VhsmClient`] over.
pub type TlsStream = StreamOwned<ClientConnection, TcpStream>;

/// Build the cross-node mTLS [`ClientConfig`]: present `client_chain` (this
/// node's `TlsIdentity` leaf, leaf-first) signed by the HSM via `sign_fn`, and
/// verify the peer server's certificate against the identity root in
/// `identity_root_pem`. Reusable across many [`connect`] calls.
pub fn client_config(
    sign_fn: impl Fn(&[u8]) -> Result<Vec<u8>, String> + Send + Sync + 'static,
    client_chain: Vec<CertificateDer<'static>>,
    identity_root_pem: &[u8],
) -> Result<ClientConfig, BoxError> {
    // Idempotent — the first caller installs the ring provider, the rest no-op.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let server_roots = hsm_rustls::roots_from_pem(identity_root_pem)?;
    let certified = hsm_rustls::hsm_certified_key(client_chain, sign_fn);
    let resolver = Arc::new(hsm_rustls::HsmClientIdentity::new(certified));

    Ok(ClientConfig::builder()
        .with_root_certificates(server_roots)
        .with_client_cert_resolver(resolver))
}

/// Dial `addr` (a peer node's cross-node listener) over mTLS and return a
/// [`VhsmClient`] ready to issue ops. `server_name` must match the peer leaf's
/// SAN. The TLS handshake — and thus the peer's authentication of THIS node —
/// happens lazily on the first op. `config` is reusable; build it once with
/// [`client_config`].
pub fn connect(
    addr: SocketAddr,
    server_name: ServerName<'static>,
    config: Arc<ClientConfig>,
) -> Result<VhsmClient<TlsStream>, BoxError> {
    let tcp = TcpStream::connect(addr)?;
    // Small request/response; latency matters more than throughput. Best-effort.
    let _ = tcp.set_nodelay(true);
    let conn = ClientConnection::new(config, server_name)?;
    Ok(VhsmClient::new(StreamOwned::new(conn, tcp)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::sync::{mpsc, Mutex};
    use std::thread;
    use std::time::Duration;

    use const_oid::db::rfc5280::{ID_KP_CLIENT_AUTH, ID_KP_SERVER_AUTH};
    use hsm::sim::SimHsm;
    use hsm::{HsmCryptoProvider, KeyRole};
    use p256::ecdsa::{DerSignature, SigningKey};
    use rand::rngs::OsRng;
    use rustls::ServerConnection;
    use vhsm_proto::{ALG_ECC_P256, HANDLE_SW_AUTHORITY, PERM_GET_PUBKEY, PERM_SIGN, PERM_VERIFY};
    use vhsm_ssd::audit::AuditLogger;
    use vhsm_ssd::crossnode::{principal_from_client_cert, serve_crossnode_connection};
    use vhsm_ssd::handle_table::HandleTable;
    use vhsm_ssd::iam::IamPolicy;
    use vhsm_ssd::tls::server_config;
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

    // Cert-building helpers — same shapes as the tls.rs / crossnode.rs tests.
    // Duplicated because Rust test helpers are crate-private; kept minimal.
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

    /// The capstone: a real `VhsmClient`, built by THIS crate's connector over
    /// an HSM-backed mTLS dial, driving a real `vhsm-ssd` cross-node listener.
    /// Proves the whole client stack end to end — client_config + connect +
    /// VhsmClient ops — against the genuine server serve loop, with the server
    /// deriving the principal from the live-handshake client cert and IAM
    /// authorizing it per-node.
    #[test]
    fn vhsm_client_drives_the_live_cross_node_listener() {
        let ca_key = SigningKey::random(&mut OsRng);
        let ca_name = Name::from_str("CN=test identity root").unwrap();
        let root_pem = ca_root_pem(&ca_key, &ca_name);

        // --- Server node ("node-b"): HSM holds the TLS identity key AND the EC
        // signer that handle sw-authority points at.
        let server_dir = tempfile::tempdir().unwrap();
        let server_hsm = SimHsm::new(PathBuf::from("unused"), server_dir.path().to_path_buf(), 0);
        let tls_kid = KeyRole::TlsIdentity.key_id();
        let server_spki = server_hsm.generate_key(tls_kid, ALG_ECC_P256).unwrap();
        // IAM matches on the handle's key_id, so the signer key_id must equal the
        // name the policy authorizes ("sw-authority").
        server_hsm
            .generate_key("sw-authority", ALG_ECC_P256)
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
        let client_roots = vhsm_ssd::tls::identity_root_store(&root_pem).unwrap();
        let server_cfg = Arc::new(
            server_config(server_hsm.clone(), tls_kid, vec![server_leaf], client_roots).unwrap(),
        );

        // Policy authorises node-a on sw-authority for sign+verify.
        let iam = IamPolicy::parse(
            "version: 1\nstatements:\n  - principals: [node-a]\n    handles: [sw-authority]\n    ops: [sign, verify, get-pubkey]\n",
        )
        .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel::<String>();

        let server = thread::spawn(move || {
            let (mut tcp, peer) = listener.accept().unwrap();
            let mut conn = ServerConnection::new(server_cfg).unwrap();
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

        // --- Client node ("node-a"): HSM-backed TLS identity, dialled via the
        // connector under test.
        let client_dir = tempfile::tempdir().unwrap();
        let client_hsm = SimHsm::new(PathBuf::from("unused"), client_dir.path().to_path_buf(), 0);
        let client_kid = "client-tls";
        let client_spki = client_hsm.generate_key(client_kid, ALG_ECC_P256).unwrap();
        let client_leaf = issue_leaf(
            &ca_key,
            &ca_name,
            "node-a",
            &client_spki,
            ID_KP_CLIENT_AUTH,
            None,
            3,
        );
        let client_hsm = Arc::new(client_hsm);
        let sign_hsm = client_hsm.clone();
        let kid_owned = client_kid.to_string();
        let sign_fn = move |m: &[u8]| {
            HsmCryptoProvider::sign(&*sign_hsm, &kid_owned, m).map_err(|e| e.to_string())
        };

        let cfg = Arc::new(client_config(sign_fn, vec![client_leaf], &root_pem).unwrap());
        let mut client = connect(addr, ServerName::try_from("localhost").unwrap(), cfg).unwrap();

        // Drive ops through the real client wrapper over the real listener.
        let msg = b"cross-node attestation challenge";
        let sig = client.sign(HANDLE_SW_AUTHORITY, msg).unwrap();
        assert!(!sig.is_empty(), "signature must be non-empty");
        assert!(
            client.verify(HANDLE_SW_AUTHORITY, msg, &sig).unwrap(),
            "the peer must verify its own signature"
        );
        let spki = client.get_pubkey(HANDLE_SW_AUTHORITY).unwrap();
        assert_eq!(spki[0], 0x30, "SPKI DER starts with a SEQUENCE tag");

        drop(client); // hang up so the server loop ends
        let node_id = rx.recv().unwrap();
        server.join().unwrap();
        assert_eq!(
            node_id, "node-a",
            "server derived the principal from the cert"
        );
    }
}
