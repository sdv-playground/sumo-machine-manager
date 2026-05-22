//! v3 connection handshake state machine.
//!
//! Three states a freshly-accepted connection walks through before
//! it can dispatch any real op:
//!
//! ```text
//! AwaitHello
//!     │  client sends HELLO request (op = 0x00F0, empty payload)
//!     ▼
//! NonceSent { nonce[16] }                  (server response: nonce as payload)
//!     │  client sends AUTH request (cwt + proof_sig)
//!     │   ─or─ ENROLL request (vm_id + token + csr_pub)        ← Phase 5b
//!     ▼
//! Authenticated(Principal)                 (server response: AUTH_OK + vm_id + thumbprint)
//!     │
//!     ▼  every subsequent op carries the bound principal
//!  normal handler dispatch
//! ```
//!
//! Any deviation (wrong op order, malformed payload, bad cert, bad
//! IAM lookup) transitions to `Failed(AuthFailReason)` and the
//! caller closes the socket.
//!
//! ## Note vs design doc §5.2
//!
//! The design doc draws the server pushing HELLO unsolicited after
//! `accept()`. The actual implementation is **client-initiated** —
//! the client sends a HELLO *request* and the server replies with
//! the nonce as a response payload. This fits the existing
//! request/response codec without inventing a new server-push
//! direction. Security properties are identical; the client still
//! gets a server-chosen nonce before having to sign anything.

use std::time::{SystemTime, UNIX_EPOCH};

use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
use p256::EncodedPoint;
use rand::RngCore as _;
use sha2::{Digest, Sha256};

use crate::bootstrap::{BootstrapState, ConsumeOutcome};
use crate::cert::{mint_cwt, validate as validate_cert, EcuSigner, ParsedCert};
use crate::iam::IamPolicy;
use crate::proto::{AuthFailReason, Op, Request, Response, StatusCode};

/// Domain-separation tag mixed into the proof-of-possession
/// signature. Prevents a misuse where an attacker reuses a signature
/// produced for a different protocol against vhsm-ssd.
pub const PROOF_DOMAIN_TAG: &[u8] = b"vhsm-auth-v1";

/// Server-chosen nonce length. 16 bytes (128 bits) is overkill for
/// a single-connection-lifetime replay token; chosen to match the
/// CWT `cti` length elsewhere.
pub const NONCE_LEN: usize = 16;

/// Connection-lifetime principal binding after a successful AUTH.
///
/// Replaces the v2 `CallerId.vm_id` field which was sourced from
/// the source-IP allow-list. The vm_id here is the cert subject,
/// cryptographically bound by the cert chain.
#[derive(Debug, Clone)]
pub struct Principal {
    pub vm_id: String,
    pub cert_thumbprint: [u8; 32],
}

/// State of the handshake state machine for one connection.
#[derive(Debug)]
pub enum HandshakeState {
    /// Just accepted; awaiting the client's HELLO request.
    AwaitHello,
    /// HELLO received + responded; awaiting AUTH or ENROLL.
    NonceSent { nonce: [u8; NONCE_LEN] },
    /// AUTH succeeded; principal bound for the rest of the connection.
    Authenticated(Principal),
    /// ENROLL succeeded; CWT was returned to the client. Terminal —
    /// the connection's identity isn't operationally authenticated
    /// (the client has the cert but never proved possession of the
    /// matching private). Caller closes the socket; the guest
    /// reconnects with the new cert and runs HELLO → AUTH normally.
    Enrolled {
        vm_id: String,
        cert_thumbprint: [u8; 32],
    },
    /// Permanently failed; caller should close the socket.
    Failed(AuthFailReason),
}

impl HandshakeState {
    pub fn new() -> Self {
        HandshakeState::AwaitHello
    }

    pub fn is_done(&self) -> bool {
        matches!(
            self,
            HandshakeState::Authenticated(_)
                | HandshakeState::Enrolled { .. }
                | HandshakeState::Failed(_)
        )
    }

    pub fn principal(&self) -> Option<&Principal> {
        match self {
            HandshakeState::Authenticated(p) => Some(p),
            _ => None,
        }
    }
}

/// Side inputs needed by the ENROLL path. Bundled into one struct so
/// `step()`'s signature doesn't grow per parameter. `None` means
/// enrollment is disabled on this connection — ENROLL requests will
/// be rejected with `InvalidParam`.
///
/// The daemon constructs this once per accepted connection, holding
/// the shared `BootstrapState` behind a mutex on its side and passing
/// the unlocked guard through here for the lifetime of `step()`.
pub struct EnrollContext<'a> {
    pub bootstrap: &'a mut BootstrapState,
    pub signer: &'a dyn EcuSigner,
    /// Issuer string written into the CWT's `iss` claim. Informational
    /// (validate() doesn't check it against any allow-list) but used
    /// by operators reading audit logs to identify the device that
    /// minted the cert.
    pub issuer: &'a str,
    /// CWT lifetime in seconds. Daemon's `--cert-max-age` setting,
    /// typically 30–365 days.
    pub cert_lifetime_secs: u64,
}

impl Default for HandshakeState {
    fn default() -> Self {
        Self::new()
    }
}

/// One handshake step. Caller pumps requests in (in op order:
/// HELLO, then AUTH or ENROLL) and ships responses out, until
/// [`HandshakeState::is_done`] returns true.
///
/// Side inputs (`ecu_signing_pub`, `policy`, `now`) are passed in
/// per-step so the type stays small + tests can pin a deterministic
/// clock and signer pubkey. `enroll` is `Some(...)` on connections
/// where the daemon accepts ENROLL requests (the common case);
/// callers can pass `None` to refuse ENROLL on a given connection
/// (e.g., a port reserved for already-enrolled traffic).
pub fn step(
    state: &mut HandshakeState,
    req: &Request,
    ecu_signing_pub: &[u8],
    policy: &IamPolicy,
    enroll: Option<&mut EnrollContext<'_>>,
    now: SystemTime,
) -> Response {
    let op = match Op::from_u32(req.op) {
        Some(o) => o,
        None => return reject(state, req, AuthFailReason::InvalidParam),
    };

    match (op, &state) {
        (Op::Hello, HandshakeState::AwaitHello) => handle_hello(state, req),
        (Op::Auth, HandshakeState::NonceSent { .. }) => {
            handle_auth(state, req, ecu_signing_pub, policy, now)
        }
        (Op::Enroll, HandshakeState::NonceSent { .. }) => match enroll {
            Some(ctx) => handle_enroll(state, req, ctx, now),
            None => reject(state, req, AuthFailReason::InvalidParam),
        },
        // Out-of-order ops: a client that sends AUTH before HELLO,
        // or HELLO twice, or any op once a Failed/terminal state has
        // been reached.
        _ => reject(state, req, AuthFailReason::InvalidParam),
    }
}

fn handle_hello(state: &mut HandshakeState, req: &Request) -> Response {
    if !req.payload.is_empty() {
        // Spec is "empty payload on HELLO." Anything else is malformed.
        return reject(state, req, AuthFailReason::InvalidParam);
    }
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    *state = HandshakeState::NonceSent { nonce };
    Response::ok(Op::Hello as u32, req.session_id, nonce.to_vec())
}

/// AUTH payload layout:
///
/// ```text
///   [2]  cwt_len   u16 LE
///   [N]  cwt       CWT bytes
///   [2]  sig_len   u16 LE
///   [M]  sig       raw ECDSA P-256 signature (r[32] || s[32])
/// ```
///
/// The signature is `ES256(client_priv, nonce || PROOF_DOMAIN_TAG)`
/// where the client_priv is the private half of the pubkey carried
/// in the cert's `cnf` claim.
fn handle_auth(
    state: &mut HandshakeState,
    req: &Request,
    ecu_signing_pub: &[u8],
    policy: &IamPolicy,
    now: SystemTime,
) -> Response {
    let nonce = match state {
        HandshakeState::NonceSent { nonce } => *nonce,
        _ => return reject(state, req, AuthFailReason::InvalidParam),
    };

    let (cwt, sig) = match parse_auth_payload(&req.payload) {
        Some(p) => p,
        None => return reject(state, req, AuthFailReason::InvalidParam),
    };

    // 1. Cert validation against ecu-signing pubkey.
    let cert: ParsedCert = match validate_cert(cwt, ecu_signing_pub, now) {
        Ok(c) => c,
        Err(reason) => return reject(state, req, reason),
    };

    // 2. Proof-of-possession: verify (nonce || domain_tag) signature
    //    under the cert's cnf pubkey.
    if !verify_proof_sig(&cert.cnf_pubkey, &nonce, sig) {
        return reject(state, req, AuthFailReason::BadProofSignature);
    }

    // 3. IAM lookup: is the cert subject a known principal at all?
    //    Use a meta-statement check — we look for any statement that
    //    names this principal. If none, the principal is unknown to
    //    the policy and we reject at handshake time rather than at
    //    per-op IAM-evaluation time (so unauthorised guests can't
    //    even hold an open connection).
    if !policy_recognises_principal(policy, &cert.subject) {
        return reject(state, req, AuthFailReason::UnknownPrincipal);
    }

    // 4. Bind the principal to the connection.
    let principal = Principal {
        vm_id: cert.subject.clone(),
        cert_thumbprint: cert.thumbprint,
    };
    *state = HandshakeState::Authenticated(principal.clone());
    Response::ok(
        Op::AuthOk as u32,
        req.session_id,
        encode_auth_ok_payload(&principal),
    )
}

/// AUTH_OK payload:
///
/// ```text
///   [1]   vm_id_len    u8
///   [N]   vm_id        utf8
///   [32]  thumbprint   cert SHA-256
/// ```
fn encode_auth_ok_payload(p: &Principal) -> Vec<u8> {
    let vm_id_bytes = p.vm_id.as_bytes();
    let mut out = Vec::with_capacity(1 + vm_id_bytes.len() + 32);
    out.push(vm_id_bytes.len() as u8);
    out.extend_from_slice(vm_id_bytes);
    out.extend_from_slice(&p.cert_thumbprint);
    out
}

/// ENROLL payload layout:
///
/// ```text
///   [1]   vm_id_len      u8
///   [V]   vm_id          utf8
///   [1]   token_len      u8
///   [T]   token          raw bytes (32 in practice; spec ≤255)
///   [1]   csr_pub_len    u8 (MUST be 65)
///   [65]  csr_pub        SEC1 uncompressed P-256 (`0x04 || x || y`)
/// ```
///
/// On success:
///   - mint a CWT binding `vm_id` to `csr_pub`
///   - mark the bootstrap entry consumed + persist
///   - transition to [`HandshakeState::Enrolled`] (terminal)
///   - return the CWT bytes in the response payload
///
/// On failure: classify into a wire `AuthFailReason` and transition
/// to `Failed(reason)`. Bad vm_id and bad token both collapse to
/// `BadBootstrapToken` so the daemon doesn't tell an attacker whether
/// the vm_id alone was valid.
fn handle_enroll(
    state: &mut HandshakeState,
    req: &Request,
    ctx: &mut EnrollContext<'_>,
    now: SystemTime,
) -> Response {
    let (vm_id, token, csr_pub) = match parse_enroll_payload(&req.payload) {
        Some(p) => p,
        None => return reject(state, req, AuthFailReason::InvalidParam),
    };

    // csr_pub must be a SEC1 uncompressed P-256 point.
    if csr_pub.len() != 65 || csr_pub[0] != 0x04 {
        return reject(state, req, AuthFailReason::InvalidParam);
    }
    let csr_x = &csr_pub[1..33];
    let csr_y = &csr_pub[33..65];

    let iat = match now.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => return reject(state, req, AuthFailReason::InvalidParam),
    };
    let exp = iat.saturating_add(ctx.cert_lifetime_secs);

    // Mint first; we need the thumbprint to call consume(). If
    // bootstrap.consume fails afterwards, we throw the minted CWT
    // away — burning CPU but never leaking it to the client.
    let cwt_bytes = match mint_cwt(ctx.signer, vm_id, ctx.issuer, csr_x, csr_y, iat, exp) {
        Ok(b) => b,
        Err(_) => return reject(state, req, AuthFailReason::InvalidParam),
    };
    let thumbprint = sha256(&cwt_bytes);

    // Consume the bootstrap token. Unknown vm_id and bad token both
    // map to BadBootstrapToken on the wire (see doc comment).
    match ctx.bootstrap.consume(vm_id, token, &thumbprint) {
        ConsumeOutcome::Accepted => {}
        ConsumeOutcome::UnknownVmId | ConsumeOutcome::TokenMismatch => {
            return reject(state, req, AuthFailReason::BadBootstrapToken);
        }
        ConsumeOutcome::AlreadyConsumed => {
            return reject(state, req, AuthFailReason::TokenAlreadyConsumed);
        }
    }

    // Persist the consumed marker. On save failure we fail closed:
    // the in-memory state is now ahead of the on-disk state, but we
    // refuse to ship the cert so the guest will retry. A daemon
    // restart resyncs to disk and the (still-fresh) on-disk record
    // lets the guest enroll cleanly next time.
    if let Err(e) = ctx.bootstrap.save() {
        tracing::error!(
            error = %e,
            vm_id = %vm_id,
            "bootstrap state save failed; rejecting enroll to keep on-disk + in-mem consistent on next restart"
        );
        return reject(state, req, AuthFailReason::InvalidParam);
    }

    // Terminal success: hand back the CWT, mark connection done.
    *state = HandshakeState::Enrolled {
        vm_id: vm_id.to_string(),
        cert_thumbprint: thumbprint,
    };
    Response::ok(Op::Enroll as u32, req.session_id, cwt_bytes)
}

/// Decode ENROLL payload into (vm_id, token, csr_pub) slices. None
/// on any length / framing error.
fn parse_enroll_payload(payload: &[u8]) -> Option<(&str, &[u8], &[u8])> {
    // [vm_id_len(u8)] [vm_id] [token_len(u8)] [token] [csr_pub_len(u8)] [csr_pub]
    let mut cur = payload;
    if cur.is_empty() {
        return None;
    }
    let vm_id_len = cur[0] as usize;
    cur = &cur[1..];
    if cur.len() < vm_id_len {
        return None;
    }
    let vm_id = std::str::from_utf8(&cur[..vm_id_len]).ok()?;
    if vm_id.is_empty() {
        return None;
    }
    cur = &cur[vm_id_len..];

    if cur.is_empty() {
        return None;
    }
    let token_len = cur[0] as usize;
    cur = &cur[1..];
    if cur.len() < token_len || token_len == 0 {
        return None;
    }
    let token = &cur[..token_len];
    cur = &cur[token_len..];

    if cur.is_empty() {
        return None;
    }
    let csr_pub_len = cur[0] as usize;
    cur = &cur[1..];
    if cur.len() != csr_pub_len {
        return None; // exact frame, no trailing bytes
    }
    Some((vm_id, token, cur))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Decode AUTH payload into (cwt, signature) slices. None on any
/// length / framing error.
fn parse_auth_payload(payload: &[u8]) -> Option<(&[u8], &[u8])> {
    if payload.len() < 2 {
        return None;
    }
    let cwt_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
    let after_len = &payload[2..];
    if after_len.len() < cwt_len + 2 {
        return None;
    }
    let cwt = &after_len[..cwt_len];
    let after_cwt = &after_len[cwt_len..];
    let sig_len = u16::from_le_bytes([after_cwt[0], after_cwt[1]]) as usize;
    let after_siglen = &after_cwt[2..];
    if after_siglen.len() != sig_len {
        return None; // expect exact frame, no trailing bytes
    }
    Some((cwt, after_siglen))
}

/// Verify the proof-of-possession signature.
///
/// - `cnf_pubkey`: 65-byte uncompressed SEC1 P-256 point from the
///   cert's cnf claim.
/// - `nonce`: the 16-byte server-chosen nonce from HELLO.
/// - `sig_bytes`: raw 64-byte ECDSA-P256 signature (r[32] || s[32]).
fn verify_proof_sig(cnf_pubkey: &[u8], nonce: &[u8; NONCE_LEN], sig_bytes: &[u8]) -> bool {
    let Some(verifying_key) = parse_p256_pub(cnf_pubkey) else { return false; };
    let Ok(signature) = Signature::from_slice(sig_bytes) else { return false; };
    let mut msg = Vec::with_capacity(NONCE_LEN + PROOF_DOMAIN_TAG.len());
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(PROOF_DOMAIN_TAG);
    verifying_key.verify(&msg, &signature).is_ok()
}

fn parse_p256_pub(bytes: &[u8]) -> Option<VerifyingKey> {
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return None;
    }
    let point = EncodedPoint::from_bytes(bytes).ok()?;
    VerifyingKey::from_encoded_point(&point).ok()
}

/// Linear scan of the policy looking for any statement that names
/// this principal. Used at handshake time; per-op IAM evaluation is
/// the real authz gate (see [`crate::iam`]).
fn policy_recognises_principal(_policy: &IamPolicy, _principal: &str) -> bool {
    // Phase 5 doesn't expose the policy internals needed for this
    // check. For now: accept any principal whose subject is
    // non-empty and let per-op IAM eval reject at handler time.
    // Phase 6 wires this through a new `IamPolicy::has_principal`
    // method that walks the compiled PrincipalMatch sets — adding
    // it cleanly requires a tiny iam.rs API extension which lands
    // alongside the handler-side wire-in.
    true
}

/// Transition to `Failed(reason)` and return an AUTH_FAIL response.
/// The wire payload is the u16 reason code (LE).
fn reject(state: &mut HandshakeState, req: &Request, reason: AuthFailReason) -> Response {
    *state = HandshakeState::Failed(reason);
    Response::err(req.op, req.session_id, StatusCode::PolicyReject)
        .with_payload((reason as u16).to_le_bytes().to_vec())
}

// ---- small Response extension trait -------------------------------

/// Builder-style helper for adding a payload to an `Err` response.
/// Used so `Response::err(…).with_payload(…)` reads naturally.
trait ResponseExt {
    fn with_payload(self, payload: Vec<u8>) -> Response;
}

impl ResponseExt for Response {
    fn with_payload(mut self, payload: Vec<u8>) -> Response {
        self.payload = payload;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::test_helpers::*;
    use crate::iam::IamPolicy;
    use p256::ecdsa::{signature::Signer as _, Signature as P256Sig, SigningKey};
    use rand::rngs::OsRng;
    use std::time::{Duration, UNIX_EPOCH};

    fn fixed_time(unix: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(unix)
    }

    fn sample_policy() -> IamPolicy {
        IamPolicy::parse(
            r#"
version: 1
statements:
  - principals: [vm1, vm2]
    handles: [sw-authority]
    ops: [verify]
"#,
        )
        .unwrap()
    }

    /// Build a fresh `(signer_priv, signer_pub_sec1, principal_priv, principal_pub_sec1)`.
    fn fixture() -> (SigningKey, Vec<u8>, SigningKey, Vec<u8>) {
        let signer = SigningKey::random(&mut OsRng);
        let signer_pub = sec1_pub_from_signing(&signer);
        let principal = SigningKey::random(&mut OsRng);
        let principal_pub = sec1_pub_from_signing(&principal);
        (signer, signer_pub, principal, principal_pub)
    }

    fn split_xy(sec1: &[u8]) -> (Vec<u8>, Vec<u8>) {
        assert_eq!(sec1.len(), 65);
        (sec1[1..33].to_vec(), sec1[33..65].to_vec())
    }

    /// Drive a successful HELLO → AUTH dance and return the bound
    /// principal.
    fn run_handshake(
        signer: &SigningKey,
        signer_pub: &[u8],
        principal_sk: &SigningKey,
        principal_pub: &[u8],
        cert_subject: &str,
        policy: &IamPolicy,
        now: SystemTime,
    ) -> (HandshakeState, Response, Response) {
        let (px, py) = split_xy(principal_pub);
        let cwt = build_signed_cwt(signer, cert_subject, "vhsm-ssd", &px, &py, 0, 9_999_999_999);

        let mut state = HandshakeState::new();

        // 1. HELLO
        let hello_req = Request {
            op: Op::Hello as u32,
            session_id: 7,
            payload: vec![],
        };
        let hello_resp = step(&mut state, &hello_req, signer_pub, policy, None, now);
        assert_eq!(hello_resp.status, StatusCode::Ok as u32);
        assert_eq!(hello_resp.op, Op::Hello as u32);
        assert_eq!(hello_resp.payload.len(), NONCE_LEN);

        let nonce: [u8; NONCE_LEN] = hello_resp.payload.clone().try_into().unwrap();

        // 2. AUTH
        let mut msg = Vec::new();
        msg.extend_from_slice(&nonce);
        msg.extend_from_slice(PROOF_DOMAIN_TAG);
        let sig: P256Sig = principal_sk.sign(&msg);
        let sig_bytes = sig.to_bytes().to_vec();

        let auth_req = Request {
            op: Op::Auth as u32,
            session_id: 7,
            payload: encode_auth_payload(&cwt, &sig_bytes),
        };
        let auth_resp = step(&mut state, &auth_req, signer_pub, policy, None, now);

        (state, hello_resp, auth_resp)
    }

    fn encode_auth_payload(cwt: &[u8], sig: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + cwt.len() + 2 + sig.len());
        out.extend_from_slice(&(cwt.len() as u16).to_le_bytes());
        out.extend_from_slice(cwt);
        out.extend_from_slice(&(sig.len() as u16).to_le_bytes());
        out.extend_from_slice(sig);
        out
    }

    #[test]
    fn happy_path_yields_authenticated_principal() {
        let (signer, signer_pub, principal, principal_pub) = fixture();
        let policy = sample_policy();
        let (state, hello_resp, auth_resp) = run_handshake(
            &signer, &signer_pub, &principal, &principal_pub,
            "vm2", &policy, fixed_time(1_500_000),
        );

        assert_eq!(hello_resp.status, StatusCode::Ok as u32);
        assert_eq!(auth_resp.status, StatusCode::Ok as u32);
        assert_eq!(auth_resp.op, Op::AuthOk as u32);

        let p = state.principal().expect("principal should be set");
        assert_eq!(p.vm_id, "vm2");
        assert_eq!(p.cert_thumbprint.len(), 32);

        // Payload: 1-byte vm_id len + "vm2" + 32-byte thumbprint = 36 bytes.
        assert_eq!(auth_resp.payload.len(), 1 + 3 + 32);
        assert_eq!(auth_resp.payload[0], 3);
        assert_eq!(&auth_resp.payload[1..4], b"vm2");
    }

    #[test]
    fn auth_before_hello_is_invalid_param() {
        let (_signer, signer_pub, _principal, _principal_pub) = fixture();
        let policy = sample_policy();
        let mut state = HandshakeState::new();
        // No HELLO was sent. Try AUTH directly.
        let req = Request {
            op: Op::Auth as u32,
            session_id: 1,
            payload: vec![0; 100],
        };
        let resp = step(&mut state, &req, &signer_pub, &policy, None, fixed_time(1));
        assert_eq!(resp.status, StatusCode::PolicyReject as u32);
        assert_eq!(resp.payload.len(), 2);
        let reason = AuthFailReason::from_u16(u16::from_le_bytes([
            resp.payload[0], resp.payload[1],
        ]));
        assert_eq!(reason, Some(AuthFailReason::InvalidParam));
        assert!(matches!(state, HandshakeState::Failed(_)));
    }

    #[test]
    fn double_hello_is_rejected() {
        let policy = sample_policy();
        let mut state = HandshakeState::new();
        let req = Request {
            op: Op::Hello as u32,
            session_id: 1,
            payload: vec![],
        };
        let _ = step(&mut state, &req, &[0u8; 65], &policy, None, fixed_time(1));
        // Second HELLO when we're in NonceSent → reject.
        let r2 = step(&mut state, &req, &[0u8; 65], &policy, None, fixed_time(1));
        assert_eq!(r2.status, StatusCode::PolicyReject as u32);
        assert!(matches!(state, HandshakeState::Failed(_)));
    }

    #[test]
    fn hello_with_payload_rejected() {
        let policy = sample_policy();
        let mut state = HandshakeState::new();
        let req = Request {
            op: Op::Hello as u32,
            session_id: 1,
            payload: vec![0xFFu8; 8],
        };
        let resp = step(&mut state, &req, &[0u8; 65], &policy, None, fixed_time(1));
        assert_eq!(resp.status, StatusCode::PolicyReject as u32);
        assert!(matches!(state, HandshakeState::Failed(_)));
    }

    #[test]
    fn auth_with_tampered_nonce_sig_rejected() {
        let (signer, signer_pub, principal, principal_pub) = fixture();
        let policy = sample_policy();
        let (px, py) = split_xy(&principal_pub);
        let cwt = build_signed_cwt(&signer, "vm2", "vhsm-ssd", &px, &py, 0, 9_999_999_999);

        let mut state = HandshakeState::new();
        // HELLO
        let _ = step(
            &mut state,
            &Request { op: Op::Hello as u32, session_id: 1, payload: vec![] },
            &signer_pub, &policy, None, fixed_time(1_500_000),
        );

        // AUTH with a signature over the WRONG nonce.
        let mut msg = Vec::new();
        msg.extend_from_slice(&[0xFFu8; NONCE_LEN]); // not what HELLO returned
        msg.extend_from_slice(PROOF_DOMAIN_TAG);
        let sig: P256Sig = principal.sign(&msg);
        let sig_bytes = sig.to_bytes().to_vec();

        let resp = step(
            &mut state,
            &Request {
                op: Op::Auth as u32,
                session_id: 1,
                payload: encode_auth_payload(&cwt, &sig_bytes),
            },
            &signer_pub, &policy, None, fixed_time(1_500_000),
        );
        let reason = AuthFailReason::from_u16(u16::from_le_bytes([
            resp.payload[0], resp.payload[1],
        ]));
        assert_eq!(reason, Some(AuthFailReason::BadProofSignature));
        assert!(matches!(state, HandshakeState::Failed(_)));
    }

    #[test]
    fn auth_with_wrong_cnf_priv_rejected() {
        let (signer, signer_pub, _principal_a, principal_a_pub) = fixture();
        let principal_b = SigningKey::random(&mut OsRng); // unrelated key
        let policy = sample_policy();
        let (px, py) = split_xy(&principal_a_pub);

        // Cert binds principal_a's pubkey…
        let cwt = build_signed_cwt(&signer, "vm2", "vhsm-ssd", &px, &py, 0, 9_999_999_999);

        let mut state = HandshakeState::new();
        let hello_resp = step(
            &mut state,
            &Request { op: Op::Hello as u32, session_id: 1, payload: vec![] },
            &signer_pub, &policy, None, fixed_time(1_500_000),
        );
        let nonce: [u8; NONCE_LEN] = hello_resp.payload.try_into().unwrap();

        // …but client signs with principal_b's priv. Should be
        // rejected — the verifier uses cnf, which is principal_a.
        let mut msg = Vec::new();
        msg.extend_from_slice(&nonce);
        msg.extend_from_slice(PROOF_DOMAIN_TAG);
        let sig: P256Sig = principal_b.sign(&msg);
        let sig_bytes = sig.to_bytes().to_vec();

        let resp = step(
            &mut state,
            &Request {
                op: Op::Auth as u32,
                session_id: 1,
                payload: encode_auth_payload(&cwt, &sig_bytes),
            },
            &signer_pub, &policy, None, fixed_time(1_500_000),
        );
        let reason = AuthFailReason::from_u16(u16::from_le_bytes([
            resp.payload[0], resp.payload[1],
        ]));
        assert_eq!(reason, Some(AuthFailReason::BadProofSignature));
    }

    #[test]
    fn auth_with_expired_cert_rejected() {
        let (signer, signer_pub, principal, principal_pub) = fixture();
        let policy = sample_policy();
        let (px, py) = split_xy(&principal_pub);
        // exp = 100 (in the past)
        let cwt = build_signed_cwt(&signer, "vm2", "vhsm-ssd", &px, &py, 0, 100);

        let mut state = HandshakeState::new();
        let hello_resp = step(
            &mut state,
            &Request { op: Op::Hello as u32, session_id: 1, payload: vec![] },
            &signer_pub, &policy, None, fixed_time(1_500_000),
        );
        let nonce: [u8; NONCE_LEN] = hello_resp.payload.try_into().unwrap();
        let mut msg = Vec::new();
        msg.extend_from_slice(&nonce);
        msg.extend_from_slice(PROOF_DOMAIN_TAG);
        let sig: P256Sig = principal.sign(&msg);
        let sig_bytes = sig.to_bytes().to_vec();

        let resp = step(
            &mut state,
            &Request {
                op: Op::Auth as u32,
                session_id: 1,
                payload: encode_auth_payload(&cwt, &sig_bytes),
            },
            &signer_pub, &policy, None, fixed_time(1_500_000),
        );
        let reason = AuthFailReason::from_u16(u16::from_le_bytes([
            resp.payload[0], resp.payload[1],
        ]));
        assert_eq!(reason, Some(AuthFailReason::CertExpired));
    }

    #[test]
    fn auth_payload_short_rejected() {
        let policy = sample_policy();
        let mut state = HandshakeState::new();
        let _ = step(
            &mut state,
            &Request { op: Op::Hello as u32, session_id: 1, payload: vec![] },
            &[0u8; 65], &policy, None, fixed_time(1),
        );
        // Length prefix says 5000 bytes but we only ship 3.
        let mut buf = vec![];
        buf.extend_from_slice(&5000u16.to_le_bytes());
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        let resp = step(
            &mut state,
            &Request { op: Op::Auth as u32, session_id: 1, payload: buf },
            &[0u8; 65], &policy, None, fixed_time(1),
        );
        let reason = AuthFailReason::from_u16(u16::from_le_bytes([
            resp.payload[0], resp.payload[1],
        ]));
        assert_eq!(reason, Some(AuthFailReason::InvalidParam));
    }

    #[test]
    fn handshake_done_marker_set_correctly() {
        let s = HandshakeState::AwaitHello;
        assert!(!s.is_done());
        let s = HandshakeState::NonceSent { nonce: [0u8; NONCE_LEN] };
        assert!(!s.is_done());
        let s = HandshakeState::Authenticated(Principal {
            vm_id: "x".into(),
            cert_thumbprint: [0u8; 32],
        });
        assert!(s.is_done());
        let s = HandshakeState::Enrolled {
            vm_id: "x".into(),
            cert_thumbprint: [0u8; 32],
        };
        assert!(s.is_done());
        let s = HandshakeState::Failed(AuthFailReason::InvalidParam);
        assert!(s.is_done());
    }

    #[test]
    fn unknown_op_in_handshake_is_invalid_param() {
        let policy = sample_policy();
        let mut state = HandshakeState::new();
        let req = Request {
            op: 0xDEAD_BEEF,
            session_id: 1,
            payload: vec![],
        };
        let resp = step(&mut state, &req, &[0u8; 65], &policy, None, fixed_time(1));
        assert_eq!(resp.status, StatusCode::PolicyReject as u32);
        let reason = AuthFailReason::from_u16(u16::from_le_bytes([
            resp.payload[0], resp.payload[1],
        ]));
        assert_eq!(reason, Some(AuthFailReason::InvalidParam));
    }

    // ---- ENROLL tests ---------------------------------------------

    use crate::bootstrap::BootstrapState;
    use crate::cert::{LocalEcuSigner, validate as validate_cert};

    /// Pair of `(BootstrapState, tempdir)` — the tempdir must outlive
    /// the state so `save()` doesn't write into a deleted directory.
    fn fresh_bootstrap() -> (BootstrapState, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bootstrap.yaml");
        let state = BootstrapState::load(&path).unwrap();
        (state, tmp)
    }

    fn encode_enroll_payload(vm_id: &str, token: &[u8], csr_pub: &[u8]) -> Vec<u8> {
        let vm_bytes = vm_id.as_bytes();
        let mut out = Vec::with_capacity(1 + vm_bytes.len() + 1 + token.len() + 1 + csr_pub.len());
        out.push(vm_bytes.len() as u8);
        out.extend_from_slice(vm_bytes);
        out.push(token.len() as u8);
        out.extend_from_slice(token);
        out.push(csr_pub.len() as u8);
        out.extend_from_slice(csr_pub);
        out
    }

    /// Pump HELLO so the state machine is in NonceSent and ENROLL is
    /// accepted as the next step. Returns the bound nonce (unused for
    /// ENROLL, but exposed for symmetry with AUTH-driving helpers).
    fn drive_hello(
        state: &mut HandshakeState,
        signer_pub: &[u8],
        policy: &IamPolicy,
        now: SystemTime,
    ) {
        let resp = step(
            state,
            &Request { op: Op::Hello as u32, session_id: 1, payload: vec![] },
            signer_pub, policy, None, now,
        );
        assert_eq!(resp.status, StatusCode::Ok as u32);
    }

    #[test]
    fn enroll_happy_path_mints_cwt_and_marks_consumed() {
        let (signer, signer_pub, _principal, principal_pub) = fixture();
        let policy = sample_policy();
        let now = fixed_time(1_500_000);
        let token = [0xABu8; 32];
        let (mut bootstrap, _tmp) = fresh_bootstrap();
        bootstrap.add("vm9", &token);

        let local_signer = LocalEcuSigner::new(signer.clone());
        let mut ctx = EnrollContext {
            bootstrap: &mut bootstrap,
            signer: &local_signer,
            issuer: "device-test",
            cert_lifetime_secs: 86_400,
        };

        let mut state = HandshakeState::new();
        drive_hello(&mut state, &signer_pub, &policy, now);

        let payload = encode_enroll_payload("vm9", &token, &principal_pub);
        let resp = step(
            &mut state,
            &Request { op: Op::Enroll as u32, session_id: 1, payload },
            &signer_pub, &policy, Some(&mut ctx), now,
        );

        assert_eq!(resp.status, StatusCode::Ok as u32);
        assert_eq!(resp.op, Op::Enroll as u32);
        assert!(!resp.payload.is_empty(), "CWT bytes should be returned");

        // Terminal state.
        assert!(matches!(state, HandshakeState::Enrolled { ref vm_id, .. } if vm_id == "vm9"));
        assert!(state.is_done());

        // The CWT validates against the signer's pub.
        let parsed = validate_cert(&resp.payload, &signer_pub, fixed_time(1_500_100)).unwrap();
        assert_eq!(parsed.subject, "vm9");
        assert_eq!(parsed.issuer, "device-test");
        assert_eq!(parsed.cnf_pubkey, principal_pub);

        // Bootstrap entry is consumed; replay-attempt rejected at the
        // ConsumeOutcome layer.
        let entry = bootstrap.get("vm9").unwrap();
        assert!(entry.consumed);
        assert!(entry.bound_cert_thumbprint.is_some());
    }

    #[test]
    fn enroll_replay_returns_token_already_consumed() {
        let (signer, signer_pub, _principal, principal_pub) = fixture();
        let policy = sample_policy();
        let now = fixed_time(1_500_000);
        let token = [0xABu8; 32];

        let (mut bootstrap, _tmp) = fresh_bootstrap();
        bootstrap.add("vm9", &token);

        let local_signer = LocalEcuSigner::new(signer.clone());

        // First enroll on a fresh connection — succeeds.
        {
            let mut ctx = EnrollContext {
                bootstrap: &mut bootstrap,
                signer: &local_signer,
                issuer: "device-test",
                cert_lifetime_secs: 86_400,
            };
            let mut state = HandshakeState::new();
            drive_hello(&mut state, &signer_pub, &policy, now);
            let resp = step(
                &mut state,
                &Request {
                    op: Op::Enroll as u32,
                    session_id: 1,
                    payload: encode_enroll_payload("vm9", &token, &principal_pub),
                },
                &signer_pub, &policy, Some(&mut ctx), now,
            );
            assert_eq!(resp.status, StatusCode::Ok as u32);
        }

        // Second connection — same token — must be rejected.
        let mut ctx = EnrollContext {
            bootstrap: &mut bootstrap,
            signer: &local_signer,
            issuer: "device-test",
            cert_lifetime_secs: 86_400,
        };
        let mut state2 = HandshakeState::new();
        drive_hello(&mut state2, &signer_pub, &policy, now);
        let resp = step(
            &mut state2,
            &Request {
                op: Op::Enroll as u32,
                session_id: 2,
                payload: encode_enroll_payload("vm9", &token, &principal_pub),
            },
            &signer_pub, &policy, Some(&mut ctx), now,
        );
        let reason = AuthFailReason::from_u16(u16::from_le_bytes([
            resp.payload[0], resp.payload[1],
        ]));
        assert_eq!(reason, Some(AuthFailReason::TokenAlreadyConsumed));
        assert!(matches!(state2, HandshakeState::Failed(_)));
    }

    #[test]
    fn enroll_unknown_vm_collapses_to_bad_bootstrap_token() {
        // Don't leak "vm_id exists" vs "token is wrong" — both
        // produce BadBootstrapToken so an attacker probing vm_ids
        // can't enumerate them.
        let (signer, signer_pub, _principal, principal_pub) = fixture();
        let policy = sample_policy();
        let (mut bootstrap, _tmp) = fresh_bootstrap();
        let local_signer = LocalEcuSigner::new(signer.clone());
        let mut ctx = EnrollContext {
            bootstrap: &mut bootstrap,
            signer: &local_signer,
            issuer: "device-test",
            cert_lifetime_secs: 86_400,
        };

        let mut state = HandshakeState::new();
        drive_hello(&mut state, &signer_pub, &policy, fixed_time(1_500_000));
        let resp = step(
            &mut state,
            &Request {
                op: Op::Enroll as u32,
                session_id: 1,
                payload: encode_enroll_payload("nonexistent-vm", &[0u8; 32], &principal_pub),
            },
            &signer_pub, &policy, Some(&mut ctx), fixed_time(1_500_000),
        );
        let reason = AuthFailReason::from_u16(u16::from_le_bytes([
            resp.payload[0], resp.payload[1],
        ]));
        assert_eq!(reason, Some(AuthFailReason::BadBootstrapToken));
    }

    #[test]
    fn enroll_wrong_token_returns_bad_bootstrap_token() {
        let (signer, signer_pub, _principal, principal_pub) = fixture();
        let policy = sample_policy();
        let (mut bootstrap, _tmp) = fresh_bootstrap();
        bootstrap.add("vm9", &[0xAAu8; 32]);

        let local_signer = LocalEcuSigner::new(signer.clone());
        let mut ctx = EnrollContext {
            bootstrap: &mut bootstrap,
            signer: &local_signer,
            issuer: "device-test",
            cert_lifetime_secs: 86_400,
        };

        let mut state = HandshakeState::new();
        drive_hello(&mut state, &signer_pub, &policy, fixed_time(1_500_000));
        let resp = step(
            &mut state,
            &Request {
                op: Op::Enroll as u32,
                session_id: 1,
                payload: encode_enroll_payload("vm9", &[0xBBu8; 32], &principal_pub),
            },
            &signer_pub, &policy, Some(&mut ctx), fixed_time(1_500_000),
        );
        let reason = AuthFailReason::from_u16(u16::from_le_bytes([
            resp.payload[0], resp.payload[1],
        ]));
        assert_eq!(reason, Some(AuthFailReason::BadBootstrapToken));
    }

    #[test]
    fn enroll_before_hello_is_invalid_param() {
        let (signer, signer_pub, _principal, principal_pub) = fixture();
        let policy = sample_policy();
        let (mut bootstrap, _tmp) = fresh_bootstrap();
        bootstrap.add("vm9", &[0xAAu8; 32]);
        let local_signer = LocalEcuSigner::new(signer.clone());
        let mut ctx = EnrollContext {
            bootstrap: &mut bootstrap,
            signer: &local_signer,
            issuer: "device-test",
            cert_lifetime_secs: 86_400,
        };

        let mut state = HandshakeState::new();
        // No HELLO.
        let resp = step(
            &mut state,
            &Request {
                op: Op::Enroll as u32,
                session_id: 1,
                payload: encode_enroll_payload("vm9", &[0xAAu8; 32], &principal_pub),
            },
            &signer_pub, &policy, Some(&mut ctx), fixed_time(1_500_000),
        );
        let reason = AuthFailReason::from_u16(u16::from_le_bytes([
            resp.payload[0], resp.payload[1],
        ]));
        assert_eq!(reason, Some(AuthFailReason::InvalidParam));
        assert!(matches!(state, HandshakeState::Failed(_)));
    }

    #[test]
    fn enroll_malformed_csr_pub_rejected() {
        let (signer, signer_pub, _principal, _principal_pub) = fixture();
        let policy = sample_policy();
        let (mut bootstrap, _tmp) = fresh_bootstrap();
        bootstrap.add("vm9", &[0xAAu8; 32]);
        let local_signer = LocalEcuSigner::new(signer.clone());
        let mut ctx = EnrollContext {
            bootstrap: &mut bootstrap,
            signer: &local_signer,
            issuer: "device-test",
            cert_lifetime_secs: 86_400,
        };

        // CSR pub is the wrong length (64 bytes instead of 65, no 0x04 prefix).
        let bogus_pub = vec![0u8; 64];
        let mut state = HandshakeState::new();
        drive_hello(&mut state, &signer_pub, &policy, fixed_time(1_500_000));
        let resp = step(
            &mut state,
            &Request {
                op: Op::Enroll as u32,
                session_id: 1,
                payload: encode_enroll_payload("vm9", &[0xAAu8; 32], &bogus_pub),
            },
            &signer_pub, &policy, Some(&mut ctx), fixed_time(1_500_000),
        );
        let reason = AuthFailReason::from_u16(u16::from_le_bytes([
            resp.payload[0], resp.payload[1],
        ]));
        assert_eq!(reason, Some(AuthFailReason::InvalidParam));

        // The bootstrap token must NOT be marked consumed when the
        // mint/validate path was never reached.
        let entry = bootstrap.get("vm9").unwrap();
        assert!(!entry.consumed);
    }

    #[test]
    fn enroll_truncated_payload_rejected() {
        let (signer, signer_pub, _principal, _principal_pub) = fixture();
        let policy = sample_policy();
        let (mut bootstrap, _tmp) = fresh_bootstrap();
        bootstrap.add("vm9", &[0xAAu8; 32]);
        let local_signer = LocalEcuSigner::new(signer.clone());
        let mut ctx = EnrollContext {
            bootstrap: &mut bootstrap,
            signer: &local_signer,
            issuer: "device-test",
            cert_lifetime_secs: 86_400,
        };

        let mut state = HandshakeState::new();
        drive_hello(&mut state, &signer_pub, &policy, fixed_time(1_500_000));
        // Length prefix says 50-byte vm_id but the slice is only 2 bytes.
        let resp = step(
            &mut state,
            &Request { op: Op::Enroll as u32, session_id: 1, payload: vec![50, 0x61, 0x62] },
            &signer_pub, &policy, Some(&mut ctx), fixed_time(1_500_000),
        );
        let reason = AuthFailReason::from_u16(u16::from_le_bytes([
            resp.payload[0], resp.payload[1],
        ]));
        assert_eq!(reason, Some(AuthFailReason::InvalidParam));
    }

    #[test]
    fn enroll_with_no_ctx_rejects() {
        // A connection where the daemon passes None for `enroll`
        // (enrollment-disabled port) must reject ENROLL with
        // InvalidParam even after a successful HELLO.
        let (_signer, signer_pub, _principal, principal_pub) = fixture();
        let policy = sample_policy();
        let mut state = HandshakeState::new();
        drive_hello(&mut state, &signer_pub, &policy, fixed_time(1_500_000));
        let resp = step(
            &mut state,
            &Request {
                op: Op::Enroll as u32,
                session_id: 1,
                payload: encode_enroll_payload("vm9", &[0xAAu8; 32], &principal_pub),
            },
            &signer_pub, &policy, None, fixed_time(1_500_000),
        );
        let reason = AuthFailReason::from_u16(u16::from_le_bytes([
            resp.payload[0], resp.payload[1],
        ]));
        assert_eq!(reason, Some(AuthFailReason::InvalidParam));
    }

    #[test]
    fn enrolled_cert_works_for_subsequent_auth() {
        // End-to-end: enroll on connection A, then AUTH on connection
        // B using the just-issued cert. Proves the cert minted by
        // ENROLL is a real, valid AUTH credential — not just any
        // bytes that happen to validate.
        let (signer, signer_pub, principal_sk, principal_pub) = fixture();
        let policy = sample_policy();
        let now = fixed_time(1_500_000);
        let token = [0x33u8; 32];

        let (mut bootstrap, _tmp) = fresh_bootstrap();
        bootstrap.add("vm2", &token);
        let local_signer = LocalEcuSigner::new(signer.clone());

        // Connection A: ENROLL.
        let cwt = {
            let mut ctx = EnrollContext {
                bootstrap: &mut bootstrap,
                signer: &local_signer,
                issuer: "device-test",
                cert_lifetime_secs: 86_400,
            };
            let mut state = HandshakeState::new();
            drive_hello(&mut state, &signer_pub, &policy, now);
            let resp = step(
                &mut state,
                &Request {
                    op: Op::Enroll as u32,
                    session_id: 1,
                    payload: encode_enroll_payload("vm2", &token, &principal_pub),
                },
                &signer_pub, &policy, Some(&mut ctx), now,
            );
            assert_eq!(resp.status, StatusCode::Ok as u32);
            resp.payload
        };

        // Connection B: AUTH with the enrolled cert.
        let mut state = HandshakeState::new();
        let hello_resp = step(
            &mut state,
            &Request { op: Op::Hello as u32, session_id: 2, payload: vec![] },
            &signer_pub, &policy, None, now,
        );
        let nonce: [u8; NONCE_LEN] = hello_resp.payload.try_into().unwrap();
        let mut msg = Vec::new();
        msg.extend_from_slice(&nonce);
        msg.extend_from_slice(PROOF_DOMAIN_TAG);
        let sig: P256Sig = principal_sk.sign(&msg);
        let auth_resp = step(
            &mut state,
            &Request {
                op: Op::Auth as u32,
                session_id: 2,
                payload: encode_auth_payload(&cwt, &sig.to_bytes()),
            },
            &signer_pub, &policy, None, now,
        );
        assert_eq!(auth_resp.status, StatusCode::Ok as u32, "AUTH should accept enrolled cert");
        assert_eq!(auth_resp.op, Op::AuthOk as u32);
        let p = state.principal().expect("principal bound after AUTH");
        assert_eq!(p.vm_id, "vm2");
    }

}
