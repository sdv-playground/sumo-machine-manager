/// Integration tests for vhsm-ssd (v3).
///
/// Tests the handler dispatch chain directly: build keystore, init handle
/// table + IAM policy, call handle_request(), verify responses.
/// No network transport needed — tests the full protocol logic in-process.
/// The handshake state machine (auth.rs) has its own unit tests; this
/// suite exercises the post-handshake dispatch path.
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use hsm::sim::SimHsm;
use hsm::HsmCryptoProvider;

use vhsm_ssd::handle_table::HandleTable;
use vhsm_ssd::handler::{self, CallerId};
use vhsm_ssd::iam::IamPolicy;
use vhsm_ssd::proto::*;

static TEST_ID: AtomicU32 = AtomicU32::new(0);

/// Simulated callers for tests. peer_ip is retained as a diagnostic
/// only in v3; vm_id is the identity (cert subject in production).
const TEST_VM: &str = "vm1";
const OTHER_VM: &str = "vm2";
const TEST_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 99, 10));
const OTHER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 99, 11));

fn caller(ip: IpAddr, vm_id: &str) -> CallerId {
    CallerId {
        peer_ip: ip,
        vm_id: vm_id.to_string(),
        cert_thumbprint: [0u8; 32],
    }
}

// --- Keystore + fixture setup ---

struct TestFixture {
    crypto: Arc<dyn HsmCryptoProvider>,
    handle_table: HandleTable,
    iam: IamPolicy,
    keystore_path: PathBuf,
}

impl TestFixture {
    fn new() -> Self {
        let id = TEST_ID.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let keystore_path = std::env::temp_dir().join(format!("vhsm-ssd-test-v2-{pid}-{id}"));

        Self::build_keystore(&keystore_path);

        let hsm = SimHsm::new(PathBuf::from("unused"), keystore_path.clone(), 5100);
        let crypto: Arc<dyn HsmCryptoProvider> = Arc::new(hsm);

        // Init handle table with well-known handles
        let mut handle_table = HandleTable::new();
        handle_table.register_well_known(
            HANDLE_IAM_SIGNING,
            "mykey",
            ALG_ECC_P256,
            PERM_SIGN | PERM_VERIFY | PERM_GET_PUBKEY | PERM_GET_CERT,
        );
        handle_table.register_well_known(
            HANDLE_STORAGE,
            "storage-key",
            ALG_AES_256,
            PERM_ENCRYPT | PERM_DECRYPT,
        );
        // restricted-key: only accessible via handle owned by OTHER_VM
        let label = [0u8; LABEL_LEN];
        handle_table.allocate(
            "restricted-key",
            ALG_AES_256,
            PERM_ENCRYPT | PERM_DECRYPT,
            OTHER_VM,
            false,
            &label,
        );

        // IAM policy:
        //  - vm1 may use mykey (signing) for sign/verify/get-pubkey/get-cert.
        //  - vm1 may use storage-key for encrypt/decrypt.
        //  - vm1 may use the SYSTEM_HANDLE for get-random + key-generate.
        //  - vm2 may use storage-key for encrypt/decrypt only (no sign).
        //  - Unknown principals match no statement → Deny by default.
        //
        // Dynamic handles (allocated below) bypass IAM and rely on
        // owner-scoping + the per-handle permitted_ops bitmask.
        let iam = IamPolicy::parse(
            r#"
version: 1
statements:
  # vm1 has broad access on mykey, INCLUDING the unrealistic
  # encrypt/get-handle-info ops — needed by tests that exercise
  # the per-handle bitmask defense (bitmask rejects encrypt on a
  # sign-only key even though IAM allows it).
  - principals: [vm1]
    handles: [mykey]
    ops: [sign, verify, get-pubkey, get-cert, get-handle-info, encrypt]
  - principals: [vm1, vm2]
    handles: [storage-key]
    ops: [encrypt, decrypt]
  - principals: [vm1, vm2]
    handles: [system]
    ops: [get-random, key-generate]
"#,
        )
        .expect("test IAM policy parses");

        Self {
            crypto,
            handle_table,
            iam,
            keystore_path,
        }
    }

    fn request(&mut self, caller: &CallerId, op: Op, payload: Vec<u8>) -> Response {
        let req = Request {
            op: op as u32,
            session_id: 1,
            payload,
        };
        // Discard AuthzOutcome — these tests assert on the Response
        // only. The Phase 7 audit-log integration is unit-tested in
        // audit.rs.
        handler::handle_request(
            &req,
            caller,
            &mut self.handle_table,
            &self.iam,
            &*self.crypto,
        )
        .0
    }

    /// Helper: build payload with handle prefix + data.
    fn with_handle(handle: u32, data: &[u8]) -> Vec<u8> {
        let mut p = Vec::with_capacity(4 + data.len());
        p.extend_from_slice(&handle.to_le_bytes());
        p.extend_from_slice(data);
        p
    }

    fn build_keystore(path: &Path) {
        use hsm::payload::*;

        let _ = std::fs::remove_dir_all(path);
        std::fs::create_dir_all(path).unwrap();

        // v2 keystore: enumeration-only slots. SimHsm's
        // generate_missing_local_keys produces the actual key
        // material on write_keystore.
        let ks = HsmKeystore {
            schema_version: SCHEMA_VERSION,
            security_version: 1,
            identities: vec![],
            slots: vec![
                KeySlot {
                    key_id: "mykey".into(),
                    key_kind: KEY_TYPE_EC_P256,
                    anchor_public_key: None,
                    allowed_guests: None,
                    allowed_ops: Some(vec![OP_SIGN, OP_VERIFY, OP_GET_PUBKEY]),
                },
                KeySlot {
                    key_id: "storage-key".into(),
                    key_kind: KEY_TYPE_AES_256,
                    anchor_public_key: None,
                    allowed_guests: None,
                    allowed_ops: Some(vec![OP_ENCRYPT, OP_DECRYPT]),
                },
                KeySlot {
                    key_id: "restricted-key".into(),
                    key_kind: KEY_TYPE_AES_256,
                    anchor_public_key: None,
                    allowed_guests: None,
                    allowed_ops: Some(vec![OP_ENCRYPT, OP_DECRYPT]),
                },
            ],
        };

        // Simulate post-CSR cert issuance for `mykey`. In production
        // a CA signs the device's CSR and the resulting cert lands
        // on disk as `keys/mykey.cert`. v2 envelopes don't carry
        // certs, so the test writes a placeholder PEM directly —
        // and does so BEFORE write_keystore so the manifest writer
        // picks it up via the on-disk file check.
        std::fs::create_dir_all(path.join("keys")).unwrap();
        let cert_pem = "-----BEGIN CERTIFICATE-----\n\
            MIIBADCB/DCBpaADAgECAhEAhAhAhAhAhAhAhAhAhAhACgYIKoZIzj0EAwIwGzEZ\n\
            MBcGA1UEAxMQdGVzdC1zZWxmLXNpZ25lZDAeFw0yNTAxMDEwMDAwMDBaFw0zNTAx\n\
            MDEwMDAwMDBaMBsxGTAXBgNVBAMTEHRlc3Qtc2VsZi1zaWduZWQwWTATBgcqhkjO\n\
            PQIBBggqhkjOPQMBBwNCAARxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n\
            -----END CERTIFICATE-----\n";
        std::fs::write(path.join("keys").join("mykey.cert"), cert_pem).unwrap();

        let hsm = SimHsm::new(PathBuf::from("unused"), path.to_path_buf(), 5100);
        hsm.write_keystore(&ks).unwrap();
        std::fs::write(path.join("provision_state"), b"1\n").unwrap();
    }
}

impl Drop for TestFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.keystore_path);
    }
}

// --- Tests ---

#[test]
fn random_bytes() {
    let mut fix = TestFixture::new();

    let count: u32 = 32;
    let resp = fix.request(
        &caller(TEST_IP, TEST_VM),
        Op::GetRandom,
        count.to_le_bytes().to_vec(),
    );

    assert_eq!(resp.status, StatusCode::Ok as u32, "random failed");
    assert_eq!(resp.payload.len(), 32);
    assert!(resp.payload.iter().any(|&b| b != 0));
}

#[test]
fn sign_and_verify() {
    let mut fix = TestFixture::new();

    // SIGN
    let data = b"hello world";
    let resp = fix.request(
        &caller(TEST_IP, TEST_VM),
        Op::Sign,
        TestFixture::with_handle(HANDLE_IAM_SIGNING, data),
    );
    assert_eq!(resp.status, StatusCode::Ok as u32, "sign failed");
    let sig = resp.payload;
    assert!(
        sig.len() >= 64 && sig.len() <= 80,
        "bad sig len: {}",
        sig.len()
    );

    // VERIFY: handle(4) + sig_len(4) + sig + hash_len(4) + hash
    let mut vp = Vec::new();
    vp.extend_from_slice(&HANDLE_IAM_SIGNING.to_le_bytes());
    vp.extend_from_slice(&(sig.len() as u32).to_le_bytes());
    vp.extend_from_slice(&sig);
    vp.extend_from_slice(&(data.len() as u32).to_le_bytes());
    vp.extend_from_slice(data);

    let req = Request {
        op: Op::Verify as u32,
        session_id: 2,
        payload: vp,
    };
    let (resp, _authz) = handler::handle_request(
        &req,
        &caller(TEST_IP, TEST_VM),
        &mut fix.handle_table,
        &fix.iam,
        &*fix.crypto,
    );
    assert_eq!(resp.status, StatusCode::Ok as u32, "verify failed");
}

#[test]
fn verify_rejects_bad_signature() {
    let mut fix = TestFixture::new();

    // Construct a syntactically valid but wrong DER signature
    let mut bad = vec![0x30, 0x44, 0x02, 0x20];
    bad.extend_from_slice(&[0xFF; 32]);
    bad.extend_from_slice(&[0x02, 0x20]);
    bad.extend_from_slice(&[0xFF; 32]);

    let mut p = Vec::new();
    p.extend_from_slice(&HANDLE_IAM_SIGNING.to_le_bytes());
    p.extend_from_slice(&(bad.len() as u32).to_le_bytes());
    p.extend_from_slice(&bad);
    p.extend_from_slice(&(4u32).to_le_bytes());
    p.extend_from_slice(b"data");

    let req = Request {
        op: Op::Verify as u32,
        session_id: 1,
        payload: p,
    };
    let (resp, _authz) = handler::handle_request(
        &req,
        &caller(TEST_IP, TEST_VM),
        &mut fix.handle_table,
        &fix.iam,
        &*fix.crypto,
    );
    assert_eq!(resp.status, StatusCode::CryptoError as u32);
}

#[test]
fn encrypt_decrypt_roundtrip() {
    let mut fix = TestFixture::new();

    let plaintext = b"secret AES-GCM data";

    // ENCRYPT
    let resp = fix.request(
        &caller(TEST_IP, TEST_VM),
        Op::Encrypt,
        TestFixture::with_handle(HANDLE_STORAGE, plaintext),
    );
    assert_eq!(resp.status, StatusCode::Ok as u32, "encrypt failed");
    let ct = resp.payload;
    assert!(ct.len() >= 12 + plaintext.len() + 16);

    // DECRYPT
    let resp = fix.request(
        &caller(TEST_IP, TEST_VM),
        Op::Decrypt,
        TestFixture::with_handle(HANDLE_STORAGE, &ct),
    );
    assert_eq!(resp.status, StatusCode::Ok as u32, "decrypt failed");
    assert_eq!(resp.payload, plaintext);
}

#[test]
fn get_pubkey() {
    let mut fix = TestFixture::new();

    let resp = fix.request(
        &caller(TEST_IP, TEST_VM),
        Op::GetPubkey,
        HANDLE_IAM_SIGNING.to_le_bytes().to_vec(),
    );
    assert_eq!(resp.status, StatusCode::Ok as u32, "get_pubkey failed");
    // Response: pubkey_len(4) + pubkey
    assert!(resp.payload.len() >= 4);
    let pk_len = u32::from_le_bytes([
        resp.payload[0],
        resp.payload[1],
        resp.payload[2],
        resp.payload[3],
    ]) as usize;
    assert_eq!(pk_len, 91, "expected 91-byte SPKI DER");
    assert_eq!(resp.payload.len(), 4 + pk_len);
}

#[test]
fn get_cert() {
    let mut fix = TestFixture::new();

    let resp = fix.request(
        &caller(TEST_IP, TEST_VM),
        Op::GetCert,
        HANDLE_IAM_SIGNING.to_le_bytes().to_vec(),
    );
    assert_eq!(resp.status, StatusCode::Ok as u32, "get_cert failed");
    assert!(resp.payload.len() >= 4);
    let c_len = u32::from_le_bytes([
        resp.payload[0],
        resp.payload[1],
        resp.payload[2],
        resp.payload[3],
    ]) as usize;
    assert!(c_len > 0);
}

#[test]
fn get_handle_info() {
    let mut fix = TestFixture::new();

    let resp = fix.request(
        &caller(TEST_IP, TEST_VM),
        Op::GetHandleInfo,
        HANDLE_IAM_SIGNING.to_le_bytes().to_vec(),
    );
    assert_eq!(resp.status, StatusCode::Ok as u32, "handle_info failed");
    assert_eq!(resp.payload.len(), 48);
    let handle = u32::from_le_bytes([
        resp.payload[0],
        resp.payload[1],
        resp.payload[2],
        resp.payload[3],
    ]);
    let alg = u32::from_le_bytes([
        resp.payload[4],
        resp.payload[5],
        resp.payload[6],
        resp.payload[7],
    ]);
    assert_eq!(handle, HANDLE_IAM_SIGNING);
    assert_eq!(alg, ALG_ECC_P256);
}

#[test]
fn invalid_handle_rejected() {
    let mut fix = TestFixture::new();

    // Use a handle that doesn't exist
    let resp = fix.request(
        &caller(TEST_IP, TEST_VM),
        Op::Sign,
        TestFixture::with_handle(0xDEAD, b"data"),
    );
    assert_eq!(resp.status, StatusCode::InvalidHandle as u32);
}

#[test]
fn dynamic_handle_ownership() {
    let mut fix = TestFixture::new();

    // Dynamic handle created by OTHER_VM is not accessible by TEST_VM
    let dynamic_handle = HANDLE_DYNAMIC_BASE; // first dynamic handle allocated in fixture
    let resp = fix.request(
        &caller(TEST_IP, TEST_VM),
        Op::Encrypt,
        TestFixture::with_handle(dynamic_handle, b"test"),
    );
    assert_eq!(
        resp.status,
        StatusCode::InvalidHandle as u32,
        "TEST_VM should not access OTHER_VM's dynamic handle"
    );

    // OTHER_VM can access its own handle
    let resp = fix.request(
        &caller(OTHER_IP, OTHER_VM),
        Op::Encrypt,
        TestFixture::with_handle(dynamic_handle, b"test"),
    );
    assert_eq!(
        resp.status,
        StatusCode::Ok as u32,
        "OTHER_VM should access its own handle"
    );
}

#[test]
fn well_known_handles_shared() {
    let mut fix = TestFixture::new();

    // Both VMs can access well-known handles (if policy allows the op)
    let resp = fix.request(
        &caller(TEST_IP, TEST_VM),
        Op::Encrypt,
        TestFixture::with_handle(HANDLE_STORAGE, b"test"),
    );
    assert_eq!(resp.status, StatusCode::Ok as u32);

    let resp = fix.request(
        &caller(OTHER_IP, OTHER_VM),
        Op::Encrypt,
        TestFixture::with_handle(HANDLE_STORAGE, b"test"),
    );
    assert_eq!(resp.status, StatusCode::Ok as u32);
}

#[test]
fn iam_rejects_unknown_principal() {
    let mut fix = TestFixture::new();

    // "stranger" isn't named in any IAM statement → default-deny.
    // peer_ip is no longer security-relevant in v3, but we pass
    // TEST_IP for log realism.
    let resp = fix.request(
        &caller(TEST_IP, "stranger"),
        Op::Sign,
        TestFixture::with_handle(HANDLE_IAM_SIGNING, b"data"),
    );
    assert_eq!(resp.status, StatusCode::PolicyReject as u32);
}

#[test]
fn iam_denies_unpermitted_op() {
    let mut fix = TestFixture::new();

    // vm2 may use storage-key for encrypt/decrypt but not mykey for sign.
    let resp = fix.request(
        &caller(OTHER_IP, OTHER_VM),
        Op::Sign,
        TestFixture::with_handle(HANDLE_IAM_SIGNING, b"data"),
    );
    assert_eq!(resp.status, StatusCode::PolicyReject as u32);
}

#[test]
fn handle_permission_denies_wrong_op() {
    let mut fix = TestFixture::new();

    // HANDLE_IAM_SIGNING has SIGN|VERIFY|GET_PUBKEY|GET_CERT — not ENCRYPT
    let resp = fix.request(
        &caller(TEST_IP, TEST_VM),
        Op::Encrypt,
        TestFixture::with_handle(HANDLE_IAM_SIGNING, b"test"),
    );
    assert_eq!(resp.status, StatusCode::PermissionDeny as u32);
}

#[test]
fn host_only_ops_rejected() {
    let mut fix = TestFixture::new();

    let req = Request {
        op: Op::KeyImport as u32,
        session_id: 1,
        payload: vec![],
    };
    let (resp, _authz) = handler::handle_request(
        &req,
        &caller(TEST_IP, TEST_VM),
        &mut fix.handle_table,
        &fix.iam,
        &*fix.crypto,
    );
    assert_eq!(resp.status, StatusCode::PolicyReject as u32);
}

#[test]
fn unknown_op_rejected() {
    let mut fix = TestFixture::new();

    let req = Request {
        op: 0xFFFF,
        session_id: 1,
        payload: vec![],
    };
    let (resp, _authz) = handler::handle_request(
        &req,
        &caller(TEST_IP, TEST_VM),
        &mut fix.handle_table,
        &fix.iam,
        &*fix.crypto,
    );
    assert_eq!(resp.status, StatusCode::InvalidParam as u32);
}
