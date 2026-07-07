//! Client side of the v3 handshake state machine.
//!
//! - [`authenticate`] — HELLO → AUTH using a persisted cert + identity key.
//!   Returns the bound `Principal`; leaves the stream ready for op dispatch.
//! - [`enroll`] — HELLO → ENROLL using a single-use bootstrap token. Persists
//!   the minted CWT, deletes the token. Caller MUST reconnect afterward.
//! - [`enroll_assisted`] — ENROLL variant with no token: the daemon resolves
//!   identity from the source IP (the host armed the vm_id at OTA install).
//!
//! Reuses the shared [`vhsm_proto`] framing + op codes + `AuthFailReason`.

use std::io::{self, Read, Write};

use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use sha2::{Digest, Sha256};

use vhsm_proto::codec::{read_response, write_request};
use vhsm_proto::{AuthFailReason, Op, Request, Response, StatusCode};

use super::persist::{self, generate_identity_keypair, AuthConfig, BOOTSTRAP_TOKEN_LEN};
use super::{NONCE_LEN, PROOF_DOMAIN_TAG};

// Handshake op codes (the numeric wire values from the shared proto).
const OP_HELLO: u32 = Op::Hello as u32;
const OP_AUTH: u32 = Op::Auth as u32;
const OP_AUTH_OK: u32 = Op::AuthOk as u32;
const OP_ENROLL: u32 = Op::Enroll as u32;
const OP_ENROLL_ASSISTED: u32 = Op::EnrollAssisted as u32;

const STATUS_OK: u32 = StatusCode::Ok as u32;

/// Bound identity returned by [`authenticate`]. Mirrors `vhsm-ssd::auth::Principal`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub vm_id: String,
    pub cert_thumbprint: [u8; 32],
}

/// Errors raised by [`authenticate`] / [`enroll`].
#[derive(Debug)]
pub enum AuthError {
    Io(io::Error),
    /// Server returned a non-success status with a structured `AuthFailReason`.
    AuthFail(AuthFailReason),
    /// Non-OK status but no valid `AuthFailReason` in the payload.
    UnknownAuthFail(u32),
    /// AUTH was requested but the cert/identity-key files are missing.
    NoCertOnDisk,
    /// ENROLL was requested but the bootstrap-token file is missing.
    NoBootstrapToken,
    /// Server replied with the wrong op code.
    UnexpectedOp {
        expected: u32,
        got: u32,
    },
    /// HELLO response wasn't a 16-byte nonce.
    BadNonce(usize),
    /// AUTH_OK payload was malformed.
    BadAuthOk(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "i/o: {e}"),
            Self::AuthFail(r) => write!(f, "auth failed: {r:?}"),
            Self::UnknownAuthFail(s) => {
                write!(f, "auth failed with unknown reason code (status={s:#x})")
            }
            Self::NoCertOnDisk => write!(f, "no persisted cert; ENROLL required"),
            Self::NoBootstrapToken => write!(f, "no bootstrap token; cannot ENROLL"),
            Self::UnexpectedOp { expected, got } => {
                write!(
                    f,
                    "wrong op in response: expected {expected:#x}, got {got:#x}"
                )
            }
            Self::BadNonce(n) => {
                write!(
                    f,
                    "HELLO returned payload of {n} bytes, expected {NONCE_LEN}"
                )
            }
            Self::BadAuthOk(s) => write!(f, "malformed AUTH_OK payload: {s}"),
        }
    }
}

impl std::error::Error for AuthError {}

impl From<io::Error> for AuthError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Run HELLO → AUTH against `stream` using the persisted cert + identity key.
pub fn authenticate<S: Read + Write>(
    stream: &mut S,
    cfg: &AuthConfig,
    session_id: u32,
) -> Result<Principal, AuthError> {
    let cwt = persist::load_cert(&cfg.cert_path)?.ok_or(AuthError::NoCertOnDisk)?;
    let id_key =
        persist::load_identity_key(&cfg.identity_key_path)?.ok_or(AuthError::NoCertOnDisk)?;

    let nonce = run_hello(stream, session_id)?;
    let proof_sig = sign_proof(&id_key, &nonce);
    let auth_payload = encode_auth_payload(&cwt, &proof_sig);

    write_request(
        stream,
        &Request {
            op: OP_AUTH,
            session_id,
            payload: auth_payload,
        },
    )?;
    let resp = read_response(stream)?;
    check_status(&resp)?;
    if resp.op != OP_AUTH_OK {
        return Err(AuthError::UnexpectedOp {
            expected: OP_AUTH_OK,
            got: resp.op,
        });
    }
    parse_auth_ok_payload(&resp.payload)
}

/// Run HELLO → ENROLL against `stream` using a single-use bootstrap token.
/// Persists the minted CWT + identity key, deletes the token. Caller MUST
/// reconnect afterward (ENROLL is a terminal handshake state).
pub fn enroll<S: Read + Write>(
    stream: &mut S,
    cfg: &AuthConfig,
    session_id: u32,
) -> Result<(), AuthError> {
    let token = persist::load_bootstrap_token(&cfg.bootstrap_token_path)?
        .ok_or(AuthError::NoBootstrapToken)?;
    debug_assert_eq!(token.len(), BOOTSTRAP_TOKEN_LEN);

    let (id_key, x, y) = generate_identity_keypair();
    let mut csr_pub = Vec::with_capacity(65);
    csr_pub.push(0x04);
    csr_pub.extend_from_slice(&x);
    csr_pub.extend_from_slice(&y);

    let _nonce = run_hello(stream, session_id)?;

    let enroll_payload = encode_enroll_payload(&cfg.vm_id, &token, &csr_pub);
    write_request(
        stream,
        &Request {
            op: OP_ENROLL,
            session_id,
            payload: enroll_payload,
        },
    )?;
    let resp = read_response(stream)?;
    check_status(&resp)?;
    if resp.op != OP_ENROLL {
        return Err(AuthError::UnexpectedOp {
            expected: OP_ENROLL,
            got: resp.op,
        });
    }

    persist::save_identity_key(&cfg.identity_key_path, &id_key)?;
    persist::save_cert(&cfg.cert_path, &resp.payload)?;
    persist::delete_bootstrap_token(&cfg.bootstrap_token_path)?;

    Ok(())
}

/// In-band enrolment without a bootstrap token — the daemon resolves identity
/// from the source IP (the host armed the vm_id at OTA install). Same
/// persistence + terminal-state semantics as [`enroll`].
pub fn enroll_assisted<S: Read + Write>(
    stream: &mut S,
    cfg: &AuthConfig,
    session_id: u32,
) -> Result<(), AuthError> {
    let (id_key, x, y) = generate_identity_keypair();
    let mut csr_pub = Vec::with_capacity(65);
    csr_pub.push(0x04);
    csr_pub.extend_from_slice(&x);
    csr_pub.extend_from_slice(&y);

    let _nonce = run_hello(stream, session_id)?;

    let payload = encode_enroll_assisted_payload(&csr_pub);
    write_request(
        stream,
        &Request {
            op: OP_ENROLL_ASSISTED,
            session_id,
            payload,
        },
    )?;
    let resp = read_response(stream)?;
    check_status(&resp)?;
    if resp.op != OP_ENROLL_ASSISTED {
        return Err(AuthError::UnexpectedOp {
            expected: OP_ENROLL_ASSISTED,
            got: resp.op,
        });
    }

    persist::save_identity_key(&cfg.identity_key_path, &id_key)?;
    persist::save_cert(&cfg.cert_path, &resp.payload)?;

    Ok(())
}

fn encode_enroll_assisted_payload(csr_pub: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + csr_pub.len());
    out.push(csr_pub.len() as u8);
    out.extend_from_slice(csr_pub);
    out
}

fn run_hello<S: Read + Write>(
    stream: &mut S,
    session_id: u32,
) -> Result<[u8; NONCE_LEN], AuthError> {
    write_request(
        stream,
        &Request {
            op: OP_HELLO,
            session_id,
            payload: vec![],
        },
    )?;
    let resp = read_response(stream)?;
    check_status(&resp)?;
    if resp.op != OP_HELLO {
        return Err(AuthError::UnexpectedOp {
            expected: OP_HELLO,
            got: resp.op,
        });
    }
    if resp.payload.len() != NONCE_LEN {
        return Err(AuthError::BadNonce(resp.payload.len()));
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&resp.payload);
    Ok(nonce)
}

fn sign_proof(id_key: &SigningKey, nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(NONCE_LEN + PROOF_DOMAIN_TAG.len());
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(PROOF_DOMAIN_TAG);
    let sig: Signature = id_key.sign(&msg);
    sig.to_vec()
}

fn encode_auth_payload(cwt: &[u8], proof_sig: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + cwt.len() + 2 + proof_sig.len());
    out.extend_from_slice(&(cwt.len() as u16).to_le_bytes());
    out.extend_from_slice(cwt);
    out.extend_from_slice(&(proof_sig.len() as u16).to_le_bytes());
    out.extend_from_slice(proof_sig);
    out
}

fn encode_enroll_payload(vm_id: &str, token: &[u8], csr_pub: &[u8]) -> Vec<u8> {
    let vm = vm_id.as_bytes();
    let mut out = Vec::with_capacity(1 + vm.len() + 1 + token.len() + 1 + csr_pub.len());
    out.push(vm.len() as u8);
    out.extend_from_slice(vm);
    out.push(token.len() as u8);
    out.extend_from_slice(token);
    out.push(csr_pub.len() as u8);
    out.extend_from_slice(csr_pub);
    out
}

fn parse_auth_ok_payload(payload: &[u8]) -> Result<Principal, AuthError> {
    // [1] vm_id_len(u8) [V] vm_id(utf-8) [32] cert_thumbprint
    if payload.is_empty() {
        return Err(AuthError::BadAuthOk("empty payload".into()));
    }
    let vm_id_len = payload[0] as usize;
    if payload.len() != 1 + vm_id_len + 32 {
        return Err(AuthError::BadAuthOk(format!(
            "expected {} bytes, got {}",
            1 + vm_id_len + 32,
            payload.len()
        )));
    }
    let vm_id = std::str::from_utf8(&payload[1..1 + vm_id_len])
        .map_err(|e| AuthError::BadAuthOk(format!("vm_id utf-8: {e}")))?
        .to_string();
    let mut thumbprint = [0u8; 32];
    thumbprint.copy_from_slice(&payload[1 + vm_id_len..]);
    Ok(Principal {
        vm_id,
        cert_thumbprint: thumbprint,
    })
}

fn check_status(resp: &Response) -> Result<(), AuthError> {
    if resp.status == STATUS_OK {
        return Ok(());
    }
    if resp.payload.len() >= 2 {
        let code = u16::from_le_bytes([resp.payload[0], resp.payload[1]]);
        if let Some(r) = AuthFailReason::from_u16(code) {
            return Err(AuthError::AuthFail(r));
        }
    }
    Err(AuthError::UnknownAuthFail(resp.status))
}

/// SHA-256 helper for computing cert thumbprints consistently.
pub fn cert_thumbprint(cwt: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(cwt);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vhsm_proto::{REQUEST_HEADER_SIZE, RESPONSE_HEADER_SIZE, VHSM_MAGIC, VHSM_VERSION};

    const STATUS_POLICY_REJECT: u32 = StatusCode::PolicyReject as u32;

    fn frame_response(op: u32, session_id: u32, status: u32, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(RESPONSE_HEADER_SIZE + payload.len());
        buf.extend_from_slice(&VHSM_MAGIC);
        buf.push(VHSM_VERSION);
        buf.extend_from_slice(&op.to_le_bytes());
        buf.extend_from_slice(&session_id.to_le_bytes());
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&status.to_le_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    /// Bidirectional in-memory stream backed by two byte queues.
    struct Pipe {
        from_server: std::collections::VecDeque<u8>,
        to_server: Vec<u8>,
    }

    impl Pipe {
        fn new(server_responses: Vec<u8>) -> Self {
            Self {
                from_server: server_responses.into(),
                to_server: Vec::new(),
            }
        }
    }

    impl Read for Pipe {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = buf.len().min(self.from_server.len());
            for slot in buf.iter_mut().take(n) {
                *slot = self.from_server.pop_front().unwrap();
            }
            Ok(n)
        }
    }

    impl Write for Pipe {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.to_server.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn write_persisted_keypair() -> (tempfile::TempDir, AuthConfig, SigningKey, Vec<u8>) {
        let t = tempfile::tempdir().unwrap();
        let cfg = AuthConfig::in_dir(t.path(), "vm-test");
        let (sk, _x, _y) = generate_identity_keypair();
        let cwt = b"\xCA\xFE\xBA\xBE\xDE\xAD\xBE\xEF".repeat(20);
        persist::save_identity_key(&cfg.identity_key_path, &sk).unwrap();
        persist::save_cert(&cfg.cert_path, &cwt).unwrap();
        (t, cfg, sk, cwt)
    }

    #[test]
    fn authenticate_happy_path_returns_principal() {
        let (_tmp, cfg, _sk, _cwt) = write_persisted_keypair();
        let session_id = 42;

        let nonce = [0xAAu8; NONCE_LEN];
        let hello_resp = frame_response(OP_HELLO, session_id, STATUS_OK, &nonce);
        let mut auth_ok_payload = Vec::new();
        auth_ok_payload.push(7u8);
        auth_ok_payload.extend_from_slice(b"vm-test");
        auth_ok_payload.extend_from_slice(&[0x33u8; 32]);
        let auth_ok_resp = frame_response(OP_AUTH_OK, session_id, STATUS_OK, &auth_ok_payload);

        let mut combined = Vec::new();
        combined.extend_from_slice(&hello_resp);
        combined.extend_from_slice(&auth_ok_resp);
        let mut pipe = Pipe::new(combined);

        let p = authenticate(&mut pipe, &cfg, session_id).unwrap();
        assert_eq!(p.vm_id, "vm-test");
        assert_eq!(p.cert_thumbprint, [0x33u8; 32]);

        let written = pipe.to_server;
        assert!(written.len() > REQUEST_HEADER_SIZE * 2);
        let op1 = u32::from_le_bytes([written[4], written[5], written[6], written[7]]);
        assert_eq!(op1, OP_HELLO);
        let payload_len_1 =
            u32::from_le_bytes([written[12], written[13], written[14], written[15]]);
        assert_eq!(payload_len_1, 0);
    }

    #[test]
    fn authenticate_without_cert_returns_no_cert_on_disk() {
        let t = tempfile::tempdir().unwrap();
        let cfg = AuthConfig::in_dir(t.path(), "vm-test");
        let mut pipe = Pipe::new(Vec::new());
        let err = authenticate(&mut pipe, &cfg, 1).unwrap_err();
        assert!(matches!(err, AuthError::NoCertOnDisk));
    }

    #[test]
    fn authenticate_hello_status_failure_returns_authfail() {
        let (_tmp, cfg, _sk, _cwt) = write_persisted_keypair();
        let payload = (AuthFailReason::InvalidParam as u16).to_le_bytes();
        let frame = frame_response(OP_HELLO, 1, STATUS_POLICY_REJECT, &payload);
        let mut pipe = Pipe::new(frame);
        let err = authenticate(&mut pipe, &cfg, 1).unwrap_err();
        assert!(matches!(
            err,
            AuthError::AuthFail(AuthFailReason::InvalidParam)
        ));
    }

    #[test]
    fn authenticate_unknown_failure_code_returns_unknown_auth_fail() {
        let (_tmp, cfg, _sk, _cwt) = write_persisted_keypair();
        let frame = frame_response(OP_HELLO, 1, STATUS_POLICY_REJECT, &[]);
        let mut pipe = Pipe::new(frame);
        let err = authenticate(&mut pipe, &cfg, 1).unwrap_err();
        assert!(matches!(err, AuthError::UnknownAuthFail(_)));
    }

    #[test]
    fn authenticate_bad_nonce_length_rejected() {
        let (_tmp, cfg, _sk, _cwt) = write_persisted_keypair();
        let frame = frame_response(OP_HELLO, 1, STATUS_OK, &[0u8; 8]);
        let mut pipe = Pipe::new(frame);
        let err = authenticate(&mut pipe, &cfg, 1).unwrap_err();
        assert!(matches!(err, AuthError::BadNonce(8)));
    }

    #[test]
    fn authenticate_wrong_response_op_rejected() {
        let (_tmp, cfg, _sk, _cwt) = write_persisted_keypair();
        let frame = frame_response(0xDEAD_BEEF, 1, STATUS_OK, &[0u8; 16]);
        let mut pipe = Pipe::new(frame);
        let err = authenticate(&mut pipe, &cfg, 1).unwrap_err();
        assert!(matches!(err, AuthError::UnexpectedOp { .. }));
    }

    #[test]
    fn auth_ok_payload_short_rejected() {
        let (_tmp, cfg, _sk, _cwt) = write_persisted_keypair();
        let nonce = [0u8; NONCE_LEN];
        let hello = frame_response(OP_HELLO, 1, STATUS_OK, &nonce);
        let auth_ok = frame_response(OP_AUTH_OK, 1, STATUS_OK, &[3u8]);
        let mut combined = Vec::new();
        combined.extend_from_slice(&hello);
        combined.extend_from_slice(&auth_ok);
        let mut pipe = Pipe::new(combined);
        let err = authenticate(&mut pipe, &cfg, 1).unwrap_err();
        assert!(matches!(err, AuthError::BadAuthOk(_)));
    }

    #[test]
    fn enroll_happy_path_persists_cert_and_deletes_token() {
        let t = tempfile::tempdir().unwrap();
        let cfg = AuthConfig::in_dir(t.path(), "vm9");
        std::fs::write(&cfg.bootstrap_token_path, [0x55u8; BOOTSTRAP_TOKEN_LEN]).unwrap();

        let session_id = 99;
        let nonce = [0xBBu8; NONCE_LEN];
        let hello = frame_response(OP_HELLO, session_id, STATUS_OK, &nonce);
        let cwt = [0xCAu8, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF].repeat(20);
        let enroll_ok = frame_response(OP_ENROLL, session_id, STATUS_OK, &cwt);
        let mut combined = Vec::new();
        combined.extend_from_slice(&hello);
        combined.extend_from_slice(&enroll_ok);
        let mut pipe = Pipe::new(combined);

        enroll(&mut pipe, &cfg, session_id).unwrap();

        assert_eq!(std::fs::read(&cfg.cert_path).unwrap(), cwt);
        assert!(cfg.identity_key_path.exists());
        assert!(!cfg.bootstrap_token_path.exists());

        let written = pipe.to_server;
        let enroll_start = REQUEST_HEADER_SIZE;
        let op = u32::from_le_bytes([
            written[enroll_start + 4],
            written[enroll_start + 5],
            written[enroll_start + 6],
            written[enroll_start + 7],
        ]);
        assert_eq!(op, OP_ENROLL);
    }

    #[test]
    fn enroll_without_token_returns_no_bootstrap_token() {
        let t = tempfile::tempdir().unwrap();
        let cfg = AuthConfig::in_dir(t.path(), "vm9");
        let mut pipe = Pipe::new(Vec::new());
        let err = enroll(&mut pipe, &cfg, 1).unwrap_err();
        assert!(matches!(err, AuthError::NoBootstrapToken));
    }

    #[test]
    fn enroll_server_rejects_bad_token() {
        let t = tempfile::tempdir().unwrap();
        let cfg = AuthConfig::in_dir(t.path(), "vm9");
        std::fs::write(&cfg.bootstrap_token_path, [0x77u8; BOOTSTRAP_TOKEN_LEN]).unwrap();

        let nonce = [0u8; NONCE_LEN];
        let hello = frame_response(OP_HELLO, 1, STATUS_OK, &nonce);
        let payload = (AuthFailReason::BadBootstrapToken as u16).to_le_bytes();
        let fail = frame_response(OP_ENROLL, 1, STATUS_POLICY_REJECT, &payload);
        let mut combined = Vec::new();
        combined.extend_from_slice(&hello);
        combined.extend_from_slice(&fail);
        let mut pipe = Pipe::new(combined);

        let err = enroll(&mut pipe, &cfg, 1).unwrap_err();
        assert!(matches!(
            err,
            AuthError::AuthFail(AuthFailReason::BadBootstrapToken)
        ));
        assert!(cfg.bootstrap_token_path.exists());
        assert!(!cfg.cert_path.exists());
        assert!(!cfg.identity_key_path.exists());
    }

    #[test]
    fn cert_thumbprint_is_sha256_of_input() {
        let tp = cert_thumbprint(b"abc");
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(tp, expected);
    }

    #[test]
    fn enroll_assisted_happy_path_persists_cert_and_no_token_file_needed() {
        let t = tempfile::tempdir().unwrap();
        let cfg = AuthConfig::in_dir(t.path(), "vm9");

        let session_id = 7;
        let nonce = [0xCCu8; NONCE_LEN];
        let hello = frame_response(OP_HELLO, session_id, STATUS_OK, &nonce);
        let cwt = [0xCAu8, 0xFE, 0xBA, 0xBE].repeat(40);
        let enroll_ok = frame_response(OP_ENROLL_ASSISTED, session_id, STATUS_OK, &cwt);
        let mut combined = Vec::new();
        combined.extend_from_slice(&hello);
        combined.extend_from_slice(&enroll_ok);
        let mut pipe = Pipe::new(combined);

        enroll_assisted(&mut pipe, &cfg, session_id).unwrap();

        assert_eq!(std::fs::read(&cfg.cert_path).unwrap(), cwt);
        assert!(cfg.identity_key_path.exists());
        assert!(!cfg.bootstrap_token_path.exists());

        let written = pipe.to_server;
        let second_start = REQUEST_HEADER_SIZE;
        let op = u32::from_le_bytes([
            written[second_start + 4],
            written[second_start + 5],
            written[second_start + 6],
            written[second_start + 7],
        ]);
        assert_eq!(op, OP_ENROLL_ASSISTED);
    }

    #[test]
    fn enroll_assisted_sends_csr_pub_only() {
        let t = tempfile::tempdir().unwrap();
        let cfg = AuthConfig::in_dir(t.path(), "vm9");

        let nonce = [0u8; NONCE_LEN];
        let hello = frame_response(OP_HELLO, 1, STATUS_OK, &nonce);
        let ok = frame_response(OP_ENROLL_ASSISTED, 1, STATUS_OK, &[0xCAu8; 200]);
        let mut combined = Vec::new();
        combined.extend_from_slice(&hello);
        combined.extend_from_slice(&ok);
        let mut pipe = Pipe::new(combined);

        enroll_assisted(&mut pipe, &cfg, 1).unwrap();
        let written = pipe.to_server;
        let payload_start = REQUEST_HEADER_SIZE + REQUEST_HEADER_SIZE;
        let payload_len_2 = u32::from_le_bytes([
            written[REQUEST_HEADER_SIZE + 12],
            written[REQUEST_HEADER_SIZE + 13],
            written[REQUEST_HEADER_SIZE + 14],
            written[REQUEST_HEADER_SIZE + 15],
        ]);
        assert_eq!(
            payload_len_2, 66,
            "ENROLL_ASSISTED payload is 1 len byte + 65 csr_pub bytes"
        );
        assert_eq!(written[payload_start], 65, "csr_pub_len byte");
        assert_eq!(written[payload_start + 1], 0x04, "SEC1 uncompressed prefix");
    }
}
