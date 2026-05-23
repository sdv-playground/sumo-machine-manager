/// Request dispatch (v3) — routes opcodes via handle table + IAM policy.

use std::net::IpAddr;

use hsm::{HsmCryptoProvider, HsmError};

use crate::handle_table::HandleTable;
use crate::iam::{IamDecision, IamPolicy};
use crate::proto::*;

/// Caller identity passed through the dispatch chain. In v3 the
/// `vm_id` is the cert `sub` claim, cryptographically bound at
/// handshake time (see [`crate::auth::Principal`]). `cert_thumbprint`
/// is the SHA-256 of the CWT bytes, logged in audit for traceability.
/// `peer_ip` is retained as a diagnostic for log lines but is NOT
/// security-relevant in v3.
#[derive(Debug, Clone)]
pub struct CallerId {
    pub peer_ip: IpAddr,
    pub vm_id: String,
    pub cert_thumbprint: [u8; 32],
}

/// Sentinel "handle name" used when evaluating IAM for ops that
/// don't operate on a specific keystore handle. Today: `GetRandom`
/// (returns entropy, no key access) and `KeyGenerate` (creates a
/// new dynamic handle). Operators who want to gate these explicitly
/// add a statement targeting `handles: [system]`.
pub const SYSTEM_HANDLE_NAME: &str = "system";

/// IAM gate outcome for one request, captured for audit log emission.
/// Distinct from `iam::IamDecision` because it has an extra `Bypass`
/// state for ops that skip IAM entirely (dynamic-handle access,
/// rejected-before-IAM-eval host-only / handshake ops).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzOutcome {
    /// IAM matched a statement → request was authorised.
    Allow { matched_statement: usize },
    /// IAM was not consulted (dynamic handles, host-only ops rejected
    /// upstream, malformed op codes). The dispatcher's downstream
    /// gates (owner-scoping, per-handle bitmask) still apply.
    Bypass,
    /// IAM evaluated and rejected.
    Deny,
}

/// Handle a single request. Returns the response to send plus the
/// IAM gate outcome — caller plumbs the outcome into the audit log
/// so operators can grep deny lines back to a specific policy
/// statement (or its absence).
pub fn handle_request(
    req: &Request,
    caller: &CallerId,
    handle_table: &mut HandleTable,
    iam: &IamPolicy,
    crypto: &dyn HsmCryptoProvider,
) -> (Response, AuthzOutcome) {
    let Some(op) = Op::from_u32(req.op) else {
        return (
            Response::err(req.op, req.session_id, StatusCode::InvalidParam),
            AuthzOutcome::Bypass,
        );
    };

    // Reject host-only ops from guest callers.
    if op.is_host_only() {
        return (
            Response::err(req.op, req.session_id, StatusCode::PolicyReject),
            AuthzOutcome::Bypass,
        );
    }

    // Handshake ops are consumed by the per-connection auth state
    // machine BEFORE the request reaches handle_request. If we got
    // here with a handshake op the dispatcher upstream has a bug —
    // reject with InvalidParam rather than panic so the daemon stays
    // alive.
    if matches!(op, Op::Hello | Op::Auth | Op::AuthOk | Op::Enroll | Op::EnrollAssisted) {
        tracing::warn!(
            op = ?op,
            vm = %caller.vm_id,
            "handshake op reached handle_request — dispatcher bug"
        );
        return (
            Response::err(req.op, req.session_id, StatusCode::InvalidParam),
            AuthzOutcome::Bypass,
        );
    }

    // For ops that operate on an existing handle (Encrypt/Decrypt/
    // Sign/Verify/Mac*/GetHandleInfo/GetPubkey/GetCert), resolve
    // first so we can name the handle to IAM. For ops without a
    // handle, use the SYSTEM_HANDLE_NAME sentinel.
    //
    // Dynamic handles (0x0100+) bypass IAM and rely on owner-scoping
    // (resolve() rejects non-owners) + per-handle bitmask perms.
    // Well-known handles always go through IAM.
    let outcome = match op {
        Op::GetRandom | Op::KeyGenerate => {
            decision_to_outcome(iam.evaluate(&caller.vm_id, SYSTEM_HANDLE_NAME, op))
        }
        _ => {
            let handle_id = peek_handle(req).unwrap_or(0);
            if handle_id >= HANDLE_DYNAMIC_BASE {
                AuthzOutcome::Bypass
            } else {
                let handle_name = handle_table
                    .get(handle_id)
                    .map(|e| e.key_id.as_str())
                    .unwrap_or("<unknown>");
                decision_to_outcome(iam.evaluate(&caller.vm_id, handle_name, op))
            }
        }
    };

    if matches!(outcome, AuthzOutcome::Deny) {
        tracing::warn!(
            vm = %caller.vm_id,
            op = ?op,
            "iam.evaluate denied"
        );
        return (
            Response::err(req.op, req.session_id, StatusCode::PolicyReject),
            outcome,
        );
    }

    let resp = match op {
        Op::GetRandom => handle_get_random(req, crypto),
        Op::KeyGenerate => handle_key_generate(req, caller, handle_table, crypto),
        Op::Encrypt => handle_crypto_with_handle(req, op, caller, handle_table, crypto),
        Op::Decrypt => handle_crypto_with_handle(req, op, caller, handle_table, crypto),
        Op::MacGenerate => handle_crypto_with_handle(req, op, caller, handle_table, crypto),
        Op::MacVerify => handle_crypto_with_handle(req, op, caller, handle_table, crypto),
        Op::Sign => handle_crypto_with_handle(req, op, caller, handle_table, crypto),
        Op::Verify => handle_verify(req, caller, handle_table, crypto),
        Op::GetHandleInfo => handle_get_handle_info(req, caller, handle_table),
        Op::GetPubkey => handle_get_pubkey(req, caller, handle_table, crypto),
        Op::GetCert => handle_get_cert(req, caller, handle_table, crypto),
        // Host-only ops already rejected above
        Op::KeyImport | Op::KeyDerive | Op::KeyDelete => unreachable!(),
        Op::Hello | Op::Auth | Op::AuthOk | Op::Enroll | Op::EnrollAssisted => unreachable!(),
    };
    (resp, outcome)
}

fn decision_to_outcome(d: IamDecision) -> AuthzOutcome {
    match d {
        IamDecision::Allow { matched_statement } => AuthzOutcome::Allow { matched_statement },
        IamDecision::Deny => AuthzOutcome::Deny,
    }
}

/// Read the handle id from the first 4 bytes of the payload, if
/// present. Used by the IAM-evaluation prelude in [`handle_request`].
fn peek_handle(req: &Request) -> Option<u32> {
    if req.payload.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([
        req.payload[0],
        req.payload[1],
        req.payload[2],
        req.payload[3],
    ]))
}

fn handle_get_random(req: &Request, crypto: &dyn HsmCryptoProvider) -> Response {
    if req.payload.len() < 4 {
        return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
    }
    let count =
        u32::from_le_bytes([req.payload[0], req.payload[1], req.payload[2], req.payload[3]])
            as usize;
    if count == 0 || count > MAX_RANDOM {
        return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
    }
    match crypto.random(count) {
        Ok(bytes) => Response::ok(req.op, req.session_id, bytes),
        Err(e) => {
            tracing::warn!(error = %e, "random failed");
            Response::err(req.op, req.session_id, StatusCode::Internal)
        }
    }
}

fn handle_key_generate(
    req: &Request,
    caller: &CallerId,
    handle_table: &mut HandleTable,
    crypto: &dyn HsmCryptoProvider,
) -> Response {
    // Parse: algorithm(4) + permitted_ops(4) + persistent(1) + pad(3) + label(32) = 44 bytes
    if req.payload.len() < 44 {
        return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
    }

    let algorithm = u32::from_le_bytes([
        req.payload[0],
        req.payload[1],
        req.payload[2],
        req.payload[3],
    ]);
    let permitted_ops = u32::from_le_bytes([
        req.payload[4],
        req.payload[5],
        req.payload[6],
        req.payload[7],
    ]);
    let persistent = req.payload[8] != 0;
    let mut label = [0u8; LABEL_LEN];
    label.copy_from_slice(&req.payload[12..12 + LABEL_LEN]);

    // Generate a key_id for internal use
    let key_id = format!("gen-{}-{}", caller.vm_id, handle_table.len());

    // Actually create the key material on disk (AES .bin or EC .priv+.pub)
    // and collect the public key DER (empty for symmetric).
    let pubkey = match crypto.generate_key(&key_id, algorithm) {
        Ok(pk) => pk,
        Err(e) => {
            tracing::warn!(key = %key_id, alg = algorithm, error = %e, "generate_key failed");
            let status = match e {
                hsm::HsmError::NotSupported(_) => StatusCode::InvalidParam,
                _ => StatusCode::Internal,
            };
            return Response::err(req.op, req.session_id, status);
        }
    };

    let handle = match handle_table.allocate(
        &key_id,
        algorithm,
        permitted_ops,
        &caller.vm_id,
        persistent,
        &label,
    ) {
        Some(h) => h,
        None => return Response::err(req.op, req.session_id, StatusCode::NoResource),
    };

    // Response: handle(4) + pubkey_len(4) + pubkey
    let mut result = Vec::with_capacity(8 + pubkey.len());
    result.extend_from_slice(&handle.to_le_bytes());
    result.extend_from_slice(&(pubkey.len() as u32).to_le_bytes());
    result.extend_from_slice(&pubkey);
    Response::ok(req.op, req.session_id, result)
}

/// Resolve handle from first 4 bytes of payload, check permissions, dispatch.
fn handle_crypto_with_handle(
    req: &Request,
    op: Op,
    caller: &CallerId,
    handle_table: &HandleTable,
    crypto: &dyn HsmCryptoProvider,
) -> Response {
    if req.payload.len() < 4 {
        return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
    }

    let handle = u32::from_le_bytes([
        req.payload[0],
        req.payload[1],
        req.payload[2],
        req.payload[3],
    ]);

    let entry = match handle_table.resolve(handle, &caller.vm_id) {
        Some(e) => e,
        None => return Response::err(req.op, req.session_id, StatusCode::InvalidHandle),
    };

    // Per-handle permission check
    if let Some(required) = op.required_perm() {
        if entry.permitted_ops & required == 0 {
            tracing::warn!(
                peer = %caller.peer_ip,
                vm = %caller.vm_id,
                op = ?op,
                handle = format!("0x{:04x}", handle),
                entry_perms = format!("0x{:04x}", entry.permitted_ops),
                required_perm = format!("0x{:08x}", required),
                "per-handle deny: entry.permitted_ops missing required bit"
            );
            return Response::err(req.op, req.session_id, StatusCode::PermissionDeny);
        }
    }

    let key_id = &entry.key_id;
    let data = &req.payload[4..];

    match op {
        Op::Sign => match crypto.sign(key_id, data) {
            Ok(sig) => Response::ok(req.op, req.session_id, sig),
            Err(e) => {
                tracing::warn!(key = %key_id, error = %e, "sign failed");
                Response::err(req.op, req.session_id, StatusCode::CryptoError)
            }
        },
        Op::Encrypt => match crypto.encrypt(key_id, data) {
            Ok(ct) => Response::ok(req.op, req.session_id, ct),
            Err(e) => {
                tracing::warn!(key = %key_id, error = %e, "encrypt failed");
                Response::err(req.op, req.session_id, StatusCode::CryptoError)
            }
        },
        Op::Decrypt => match crypto.decrypt(key_id, data) {
            Ok(pt) => Response::ok(req.op, req.session_id, pt),
            Err(e) => {
                tracing::warn!(key = %key_id, error = %e, "decrypt failed");
                Response::err(req.op, req.session_id, StatusCode::CryptoError)
            }
        },
        Op::MacGenerate => {
            // payload: data (variable length)
            match crypto.mac_generate(key_id, data) {
                Ok(mac) => Response::ok(req.op, req.session_id, mac),
                Err(e) => {
                    tracing::warn!(key = %key_id, error = %e, "mac_generate failed");
                    Response::err(req.op, req.session_id, StatusCode::CryptoError)
                }
            }
        },
        Op::MacVerify => {
            // payload: mac_len(4) + mac + data
            if data.len() < 4 {
                return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
            }
            let mac_len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
            if data.len() < 4 + mac_len {
                return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
            }
            let mac_tag = &data[4..4 + mac_len];
            let mac_data = &data[4 + mac_len..];
            match crypto.mac_verify(key_id, mac_data, mac_tag) {
                Ok(true) => Response::ok(req.op, req.session_id, Vec::new()),
                Ok(false) => Response::err(req.op, req.session_id, StatusCode::CryptoError),
                Err(e) => {
                    tracing::warn!(key = %key_id, error = %e, "mac_verify failed");
                    Response::err(req.op, req.session_id, StatusCode::CryptoError)
                }
            }
        },
        _ => Response::err(req.op, req.session_id, StatusCode::InvalidParam),
    }
}

fn handle_verify(
    req: &Request,
    caller: &CallerId,
    handle_table: &HandleTable,
    crypto: &dyn HsmCryptoProvider,
) -> Response {
    // Payload: handle(4) + sig_len(4) + signature + hash_len(4) + hash
    if req.payload.len() < 12 {
        return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
    }

    let handle = u32::from_le_bytes([
        req.payload[0],
        req.payload[1],
        req.payload[2],
        req.payload[3],
    ]);

    let entry = match handle_table.resolve(handle, &caller.vm_id) {
        Some(e) => e,
        None => return Response::err(req.op, req.session_id, StatusCode::InvalidHandle),
    };

    if entry.permitted_ops & PERM_VERIFY == 0 {
        tracing::warn!(
            peer = %caller.peer_ip, vm = %caller.vm_id,
            op = "verify",
            entry_perms = format!("0x{:04x}", entry.permitted_ops),
            "per-handle deny: PERM_VERIFY missing"
        );
        return Response::err(req.op, req.session_id, StatusCode::PermissionDeny);
    }

    let rest = &req.payload[4..];
    if rest.len() < 4 {
        return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
    }
    let sig_len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    if rest.len() < 4 + sig_len + 4 {
        return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
    }
    let signature = &rest[4..4 + sig_len];
    let hash_start = 4 + sig_len;
    let hash_len =
        u32::from_le_bytes([rest[hash_start], rest[hash_start + 1], rest[hash_start + 2], rest[hash_start + 3]])
            as usize;
    if rest.len() < hash_start + 4 + hash_len {
        return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
    }
    let hash = &rest[hash_start + 4..hash_start + 4 + hash_len];

    match crypto.verify(&entry.key_id, hash, signature) {
        Ok(true) => Response::ok(req.op, req.session_id, Vec::new()),
        Ok(false) => Response::err(req.op, req.session_id, StatusCode::CryptoError),
        Err(e) => {
            tracing::warn!(key = %entry.key_id, error = %e, "verify failed");
            Response::err(req.op, req.session_id, StatusCode::CryptoError)
        }
    }
}

fn handle_get_handle_info(
    req: &Request,
    caller: &CallerId,
    handle_table: &HandleTable,
) -> Response {
    if req.payload.len() < 4 {
        return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
    }

    let handle = u32::from_le_bytes([
        req.payload[0],
        req.payload[1],
        req.payload[2],
        req.payload[3],
    ]);

    let entry = match handle_table.resolve(handle, &caller.vm_id) {
        Some(e) => e,
        None => return Response::err(req.op, req.session_id, StatusCode::InvalidHandle),
    };

    // Response: handle(4) + algorithm(4) + permitted_ops(4) + persistent(1) + pad(3) + label(32) = 48
    let mut result = Vec::with_capacity(48);
    result.extend_from_slice(&entry.handle.to_le_bytes());
    result.extend_from_slice(&entry.algorithm.to_le_bytes());
    result.extend_from_slice(&entry.permitted_ops.to_le_bytes());
    result.push(if entry.persistent { 1 } else { 0 });
    result.extend_from_slice(&[0u8; 3]); // pad
    result.extend_from_slice(&entry.label);
    Response::ok(req.op, req.session_id, result)
}

fn handle_get_pubkey(
    req: &Request,
    caller: &CallerId,
    handle_table: &HandleTable,
    crypto: &dyn HsmCryptoProvider,
) -> Response {
    if req.payload.len() < 4 {
        return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
    }

    let handle = u32::from_le_bytes([
        req.payload[0],
        req.payload[1],
        req.payload[2],
        req.payload[3],
    ]);

    let entry = match handle_table.resolve(handle, &caller.vm_id) {
        Some(e) => e,
        None => return Response::err(req.op, req.session_id, StatusCode::InvalidHandle),
    };

    if entry.permitted_ops & PERM_GET_PUBKEY == 0 {
        tracing::warn!(
            peer = %caller.peer_ip, vm = %caller.vm_id,
            op = "get_pubkey",
            entry_perms = format!("0x{:04x}", entry.permitted_ops),
            "per-handle deny: PERM_GET_PUBKEY missing"
        );
        return Response::err(req.op, req.session_id, StatusCode::PermissionDeny);
    }

    match crypto.get_public_key_der(&entry.key_id) {
        Ok(pk) => {
            let mut result = Vec::with_capacity(4 + pk.len());
            result.extend_from_slice(&(pk.len() as u32).to_le_bytes());
            result.extend_from_slice(&pk);
            Response::ok(req.op, req.session_id, result)
        }
        Err(HsmError::KeyNotFound(_)) => {
            Response::err(req.op, req.session_id, StatusCode::InvalidHandle)
        }
        Err(e) => {
            tracing::warn!(key = %entry.key_id, error = %e, "get_pubkey failed");
            Response::err(req.op, req.session_id, StatusCode::Internal)
        }
    }
}

fn handle_get_cert(
    req: &Request,
    caller: &CallerId,
    handle_table: &HandleTable,
    crypto: &dyn HsmCryptoProvider,
) -> Response {
    if req.payload.len() < 4 {
        return Response::err(req.op, req.session_id, StatusCode::InvalidParam);
    }

    let handle = u32::from_le_bytes([
        req.payload[0],
        req.payload[1],
        req.payload[2],
        req.payload[3],
    ]);

    let entry = match handle_table.resolve(handle, &caller.vm_id) {
        Some(e) => e,
        None => return Response::err(req.op, req.session_id, StatusCode::InvalidHandle),
    };

    if entry.permitted_ops & PERM_GET_CERT == 0 {
        tracing::warn!(
            peer = %caller.peer_ip, vm = %caller.vm_id,
            op = "get_cert",
            entry_perms = format!("0x{:04x}", entry.permitted_ops),
            "per-handle deny: PERM_GET_CERT missing"
        );
        return Response::err(req.op, req.session_id, StatusCode::PermissionDeny);
    }

    match crypto.get_certificate_der(&entry.key_id) {
        Ok(cert) => {
            let mut result = Vec::with_capacity(4 + cert.len());
            result.extend_from_slice(&(cert.len() as u32).to_le_bytes());
            result.extend_from_slice(&cert);
            Response::ok(req.op, req.session_id, result)
        }
        Err(HsmError::KeyNotFound(_)) => {
            Response::err(req.op, req.session_id, StatusCode::InvalidHandle)
        }
        Err(e) => {
            tracing::warn!(key = %entry.key_id, error = %e, "get_cert failed");
            Response::err(req.op, req.session_id, StatusCode::Internal)
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use hsm::sim::SimHsm;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    fn new_hsm() -> (SimHsm, PathBuf, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let keystore = PathBuf::from(tmp.path());
        // Matches SimHsm's internal keys_dir() — keystore_path/keys.
        let keys_dir = keystore.join("keys");
        let hsm = SimHsm::new(PathBuf::from("unused"), keystore, 0);
        (hsm, keys_dir, tmp)
    }

    fn caller(vm_id: &str) -> CallerId {
        CallerId {
            peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            vm_id: vm_id.to_string(),
            cert_thumbprint: [0u8; 32],
        }
    }

    /// Build a key_generate payload: algorithm(4) + permitted_ops(4) +
    /// persistent(1) + pad(3) + label(32) = 44 bytes.
    fn make_keygen_payload(alg: u32, permitted_ops: u32) -> Vec<u8> {
        let mut p = Vec::with_capacity(44);
        p.extend_from_slice(&alg.to_le_bytes());
        p.extend_from_slice(&permitted_ops.to_le_bytes());
        p.push(0); // persistent=false
        p.extend_from_slice(&[0u8; 3]); // pad
        p.extend_from_slice(&[0u8; LABEL_LEN]); // empty label
        p
    }

    #[test]
    fn key_generate_aes256_creates_real_key_and_returns_handle() {
        let (hsm, keys_dir, _tmp) = new_hsm();
        let mut table = HandleTable::new();

        let req = Request {
            op: Op::KeyGenerate as u32,
            session_id: 0,
            payload: make_keygen_payload(
                ALG_AES_256,
                PERM_ENCRYPT | PERM_DECRYPT | PERM_MAC_GEN | PERM_MAC_VFY,
            ),
        };
        let resp = handle_key_generate(&req, &caller("vm1"), &mut table, &hsm);
        assert_eq!(resp.status, StatusCode::Ok as u32);

        // Response: handle(4) + pubkey_len(4) + pubkey
        assert!(resp.payload.len() >= 8);
        let handle = u32::from_le_bytes(resp.payload[0..4].try_into().unwrap());
        let pubkey_len = u32::from_le_bytes(resp.payload[4..8].try_into().unwrap());
        assert_eq!(pubkey_len, 0, "AES is symmetric — no public key");
        assert!(handle >= 0x0100, "dynamic handle in 0x0100+ range");

        // Key file must actually exist on disk (regression test for the
        // pre-fix TODO where the handler allocated handles without calling
        // generate_key — mac-generate then failed with CRYPTO_ERROR).
        assert!(keys_dir.join("gen-vm1-0.bin").exists());
    }

    #[test]
    fn key_generate_ecc_p256_returns_pubkey_in_response() {
        let (hsm, keys_dir, _tmp) = new_hsm();
        let mut table = HandleTable::new();

        let req = Request {
            op: Op::KeyGenerate as u32,
            session_id: 0,
            payload: make_keygen_payload(ALG_ECC_P256, PERM_SIGN | PERM_VERIFY | PERM_GET_PUBKEY),
        };
        let resp = handle_key_generate(&req, &caller("vm1"), &mut table, &hsm);
        assert_eq!(resp.status, StatusCode::Ok as u32);

        let pubkey_len = u32::from_le_bytes(resp.payload[4..8].try_into().unwrap()) as usize;
        assert!(pubkey_len > 0, "EC-P256 must return a public key");
        assert!(resp.payload.len() >= 8 + pubkey_len);
        let pubkey = &resp.payload[8..8 + pubkey_len];
        // SubjectPublicKeyInfo DER starts with SEQUENCE (0x30).
        assert_eq!(pubkey[0], 0x30);

        assert!(keys_dir.join("gen-vm1-0.priv").exists());
        assert!(keys_dir.join("gen-vm1-0.pub").exists());
    }

    #[test]
    fn key_generate_unsupported_alg_rejected() {
        let (hsm, _keys_dir, _tmp) = new_hsm();
        let mut table = HandleTable::new();

        // 0x0099 isn't on the wire; SimHsm returns NotSupported, handler maps to InvalidParam.
        let req = Request {
            op: Op::KeyGenerate as u32,
            session_id: 0,
            payload: make_keygen_payload(0x0099, 0),
        };
        let resp = handle_key_generate(&req, &caller("vm1"), &mut table, &hsm);
        assert_eq!(
            resp.status,
            StatusCode::InvalidParam as u32,
            "unsupported alg should map to InvalidParam"
        );
    }

    #[test]
    fn key_generate_ed25519_returns_pubkey_and_allocates_handle() {
        let (hsm, _keys_dir, _tmp) = new_hsm();
        let mut table = HandleTable::new();

        let req = Request {
            op: Op::KeyGenerate as u32,
            session_id: 0,
            payload: make_keygen_payload(ALG_ED25519, PERM_SIGN | PERM_VERIFY),
        };
        let resp = handle_key_generate(&req, &caller("vm1"), &mut table, &hsm);
        assert_eq!(resp.status, StatusCode::Ok as u32);
        // result layout: handle(4) + pubkey_len(4) + pubkey
        assert!(resp.payload.len() > 8, "expected pubkey DER, got len={}", resp.payload.len());
        let pubkey_len = u32::from_le_bytes([
            resp.payload[4], resp.payload[5], resp.payload[6], resp.payload[7],
        ]) as usize;
        assert!(pubkey_len > 32, "Ed25519 SPKI is ~44 bytes, got {pubkey_len}");
    }

    #[test]
    fn key_generate_aes128_allocates_handle() {
        let (hsm, _keys_dir, _tmp) = new_hsm();
        let mut table = HandleTable::new();
        let req = Request {
            op: Op::KeyGenerate as u32,
            session_id: 0,
            payload: make_keygen_payload(ALG_AES_128, PERM_ENCRYPT | PERM_DECRYPT),
        };
        let resp = handle_key_generate(&req, &caller("vm1"), &mut table, &hsm);
        assert_eq!(resp.status, StatusCode::Ok as u32);
    }

    #[test]
    fn key_generate_hmac_sha256_allocates_handle() {
        let (hsm, _keys_dir, _tmp) = new_hsm();
        let mut table = HandleTable::new();
        let req = Request {
            op: Op::KeyGenerate as u32,
            session_id: 0,
            payload: make_keygen_payload(ALG_HMAC_SHA256, PERM_MAC_GEN | PERM_MAC_VFY),
        };
        let resp = handle_key_generate(&req, &caller("vm1"), &mut table, &hsm);
        assert_eq!(resp.status, StatusCode::Ok as u32);
    }

    #[test]
    fn key_generate_then_mac_generate_roundtrip() {
        // End-to-end integration test: without the fix, the dynamic handle
        // pointed at a non-existent key_id and `mac_generate` failed with
        // `CRYPTO_ERROR` because `get_key_info` couldn't find the key.
        use hsm::HsmCryptoProvider;
        let (hsm, _keys_dir, _tmp) = new_hsm();
        let mut table = HandleTable::new();

        let req = Request {
            op: Op::KeyGenerate as u32,
            session_id: 0,
            payload: make_keygen_payload(
                ALG_AES_256,
                PERM_ENCRYPT | PERM_DECRYPT | PERM_MAC_GEN | PERM_MAC_VFY,
            ),
        };
        let resp = handle_key_generate(&req, &caller("vm-test"), &mut table, &hsm);
        assert_eq!(resp.status, StatusCode::Ok as u32);
        let handle = u32::from_le_bytes(resp.payload[0..4].try_into().unwrap());

        let key_id = table.get(handle).expect("handle in table").key_id.clone();
        let mac = hsm.mac_generate(&key_id, b"hello").unwrap();
        assert_eq!(mac.len(), 16, "AES-CMAC tag");
        assert!(hsm.mac_verify(&key_id, b"hello", &mac).unwrap());
    }

    /// Host-only ops (KeyImport / KeyDerive / KeyDelete) must return
    /// POLICY_REJECT for guest callers, regardless of IAM policy. This
    /// is enforced at `handle_request` entry — earlier than IAM
    /// evaluation — so even a wildcard-allow policy can't open them up
    /// to guests. The gate is the only thing keeping a guest from
    /// trying to import keys into the host keystore over the wire.
    #[test]
    fn host_only_ops_rejected_from_guest_with_policy_reject() {
        use crate::iam::IamPolicy;
        let (hsm, _keys_dir, _tmp) = new_hsm();
        let mut table = HandleTable::new();
        // Wildcard-allow policy — proves the host-only gate fires
        // BEFORE IAM evaluation. If IAM were the only gate, this
        // wide-open policy would let KeyImport through.
        let iam = IamPolicy::parse(
            "version: 1\nstatements:\n  - principals: [\"*\"]\n    handles: [\"*\"]\n    ops: [\"*\"]\n",
        )
        .expect("policy parses");

        for op in [Op::KeyImport, Op::KeyDerive, Op::KeyDelete] {
            let req = Request {
                op: op as u32,
                session_id: 0,
                payload: vec![],
            };
            let (resp, outcome) = handle_request(&req, &caller("vm1"), &mut table, &iam, &hsm);
            assert_eq!(
                resp.status,
                StatusCode::PolicyReject as u32,
                "host-only op {op:?} must return POLICY_REJECT to guests",
            );
            // The gate fires before IAM, so outcome is Bypass — there's
            // no statement to attribute the reject to in the audit log.
            assert!(
                matches!(outcome, AuthzOutcome::Bypass),
                "host-only reject should bypass IAM (got {outcome:?})"
            );
        }
    }
}
