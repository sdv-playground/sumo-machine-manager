//! Platform-agnostic client for the vHSM wire protocol (v3).
//!
//! Speaks the same [`vhsm_proto`] framing as the `vhsm-ssd` daemon, over any
//! `Read + Write` stream — a plain `TcpStream` on the in-vehicle private
//! bridge, or a mutually-authenticated rustls TLS stream for cross-node calls.
//! The transport (and, for cross-node, the mTLS handshake that establishes the
//! calling node's identity) is the *caller's* concern; this crate only encodes
//! ops and decodes responses. That keeps it portable — `guest-vm-sdk` can reuse
//! it unchanged, and a host cross-node service can hand it an HSM-backed TLS
//! stream.
//!
//! ## Identity (read before wiring auth)
//!
//! This client does **not** perform the in-band v3 CWT handshake
//! (HELLO/AUTH/ENROLL). That flow authenticates a *guest VM* by source IP plus
//! a bootstrap cert and is spoken by the C guest client (`libvhsm`). The Rust
//! client targets the *cross-node* path, where the principal is the TLS client
//! certificate — the node's HSM-backed `TlsIdentity` leaf — and the peer's IAM
//! authorises that node per-op. There is no `random component does cross-node
//! calls` hole: a caller can only obtain a usable stream by completing the mTLS
//! handshake with a cert the peer's `identity-root` trusts, and the peer then
//! gates every op through IAM keyed on the cert subject.
//!
//! `session_id` here is a client-side correlation counter, not a security
//! token; the daemon echoes it back and the client checks it to catch a desync.

use std::io::{self, Read, Write};

use vhsm_proto::codec::{read_response, write_request};
use vhsm_proto::{Op, Request, StatusCode};

/// An error from a vHSM client call.
#[derive(Debug)]
pub enum ClientError {
    /// Transport-level failure (connection closed, short read/write).
    Io(io::Error),
    /// The daemon returned a non-OK status for the op.
    Status(StatusCode),
    /// The daemon returned a status word this crate doesn't recognise.
    UnknownStatus(u32),
    /// The response didn't match the request (op or session mismatch), or a
    /// length-prefixed field was truncated — a desync or a malformed peer.
    Protocol(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "vhsm transport error: {e}"),
            ClientError::Status(s) => write!(f, "vhsm daemon returned status {s:?}"),
            ClientError::UnknownStatus(v) => {
                write!(f, "vhsm daemon returned unknown status 0x{v:08x}")
            }
            ClientError::Protocol(m) => write!(f, "vhsm protocol error: {m}"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ClientError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        ClientError::Io(e)
    }
}

/// Result alias for client calls.
pub type Result<T> = std::result::Result<T, ClientError>;

/// A synchronous vHSM client over a single connected stream.
///
/// One request/response per op, strictly ordered — the daemon serves a
/// connection sequentially, so the client mirrors that. Construct with an
/// already-connected (and, for cross-node, already-authenticated) stream.
pub struct VhsmClient<S> {
    stream: S,
    next_session: u32,
}

impl<S: Read + Write> VhsmClient<S> {
    /// Wrap a connected stream. The stream must already be open; for the
    /// cross-node path it must already have completed the mTLS handshake.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            next_session: 1,
        }
    }

    /// Consume the client and return the underlying stream (e.g. to close it
    /// explicitly or reclaim a TLS connection).
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// One request/response round-trip. Returns the OK payload, or maps a
    /// non-OK status into [`ClientError::Status`]. Verifies the response's op
    /// and session id match the request so a framing desync fails loud rather
    /// than silently returning the wrong op's bytes.
    fn call(&mut self, op: Op, payload: Vec<u8>) -> Result<Vec<u8>> {
        let session_id = self.next_session;
        // Never reuse 0; wrap back to 1 so the id stays a tidy nonzero counter.
        self.next_session = self.next_session.wrapping_add(1).max(1);

        let req = Request {
            op: op as u32,
            session_id,
            payload,
        };
        write_request(&mut self.stream, &req)?;
        let resp = read_response(&mut self.stream)?;

        if resp.op != op as u32 {
            return Err(ClientError::Protocol(format!(
                "response op 0x{:04x} does not match request op 0x{:04x}",
                resp.op, op as u32
            )));
        }
        if resp.session_id != session_id {
            return Err(ClientError::Protocol(format!(
                "response session {} does not match request session {}",
                resp.session_id, session_id
            )));
        }

        match StatusCode::from_u32(resp.status) {
            Some(StatusCode::Ok) => Ok(resp.payload),
            Some(s) => Err(ClientError::Status(s)),
            None => Err(ClientError::UnknownStatus(resp.status)),
        }
    }

    /// `GetRandom`: request `count` random bytes (the daemon caps this at
    /// `vhsm_proto::MAX_RANDOM`).
    pub fn get_random(&mut self, count: usize) -> Result<Vec<u8>> {
        self.call(Op::GetRandom, (count as u32).to_le_bytes().to_vec())
    }

    /// `Sign`: sign `message` with the key behind `handle`. Returns the
    /// signature (DER `r || s` for P-256). The daemon hashes the message
    /// internally (SHA-256 for P-256) — pass the message, not a digest.
    pub fn sign(&mut self, handle: u32, message: &[u8]) -> Result<Vec<u8>> {
        let mut payload = handle.to_le_bytes().to_vec();
        payload.extend_from_slice(message);
        self.call(Op::Sign, payload)
    }

    /// `Verify`: check `signature` over `message` against the key behind
    /// `handle`. Returns `true` for a valid signature and `false` for a
    /// cryptographic mismatch (the daemon's `CryptoError` for a bad sig is
    /// surfaced as `Ok(false)`, not an `Err`). A missing handle or a denied
    /// permission still returns `Err`.
    pub fn verify(&mut self, handle: u32, message: &[u8], signature: &[u8]) -> Result<bool> {
        // payload: handle(4) + sig_len(4) + sig + msg_len(4) + msg
        let mut payload = Vec::with_capacity(12 + signature.len() + message.len());
        payload.extend_from_slice(&handle.to_le_bytes());
        payload.extend_from_slice(&(signature.len() as u32).to_le_bytes());
        payload.extend_from_slice(signature);
        payload.extend_from_slice(&(message.len() as u32).to_le_bytes());
        payload.extend_from_slice(message);
        match self.call(Op::Verify, payload) {
            Ok(_) => Ok(true),
            Err(ClientError::Status(StatusCode::CryptoError)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// `GetPubkey`: the SubjectPublicKeyInfo DER for the key behind `handle`.
    pub fn get_pubkey(&mut self, handle: u32) -> Result<Vec<u8>> {
        let resp = self.call(Op::GetPubkey, handle.to_le_bytes().to_vec())?;
        read_len_prefixed(&resp)
    }

    /// `GetCert`: the X.509 certificate DER for the key behind `handle`.
    pub fn get_cert(&mut self, handle: u32) -> Result<Vec<u8>> {
        let resp = self.call(Op::GetCert, handle.to_le_bytes().to_vec())?;
        read_len_prefixed(&resp)
    }

    /// `Encrypt`: AES-GCM `plaintext` under the key behind `handle`. Returns
    /// `iv(12) || ciphertext || tag`.
    pub fn encrypt(&mut self, handle: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut payload = handle.to_le_bytes().to_vec();
        payload.extend_from_slice(plaintext);
        self.call(Op::Encrypt, payload)
    }

    /// `Decrypt`: inverse of [`encrypt`](Self::encrypt) — expects
    /// `iv(12) || ciphertext || tag`.
    pub fn decrypt(&mut self, handle: u32, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut payload = handle.to_le_bytes().to_vec();
        payload.extend_from_slice(ciphertext);
        self.call(Op::Decrypt, payload)
    }
}

/// Strip a `u32` little-endian length prefix and return the body. `GetPubkey`
/// and `GetCert` both reply with `len(4) + bytes`.
fn read_len_prefixed(buf: &[u8]) -> Result<Vec<u8>> {
    if buf.len() < 4 {
        return Err(ClientError::Protocol(format!(
            "length-prefixed payload too short: {} bytes",
            buf.len()
        )));
    }
    let n = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + n {
        return Err(ClientError::Protocol(format!(
            "length prefix claims {n} bytes but only {} present",
            buf.len() - 4
        )));
    }
    Ok(buf[4..4 + n].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::thread;

    use hsm::sim::SimHsm;
    use hsm::HsmCryptoProvider;
    use vhsm_proto::codec::{read_request, write_response};
    use vhsm_proto::{ALG_ECC_P256, PERM_GET_PUBKEY, PERM_SIGN, PERM_VERIFY};
    use vhsm_ssd::handle_table::HandleTable;
    use vhsm_ssd::handler::{handle_request, CallerId};
    use vhsm_ssd::iam::IamPolicy;

    // A well-known handle slot reused as a test EC-P256 signer.
    const TEST_HANDLE: u32 = 0x0002;

    /// Spawn a one-connection loopback vHSM daemon backed by a real `SimHsm`
    /// with a single EC-P256 signer registered at [`TEST_HANDLE`]. This is the
    /// genuine server dispatch (`handle_request`) over a real socket, so the
    /// client's framing is proven against the code it will talk to in
    /// production — not a hand-rolled mock. Serves until the client hangs up.
    fn spawn_test_daemon() -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let tmp = tempfile::tempdir().unwrap();
            let hsm = SimHsm::new(PathBuf::from("unused"), tmp.path().to_path_buf(), 0);
            HsmCryptoProvider::generate_key(&hsm, "node-signer", ALG_ECC_P256).unwrap();

            let mut table = HandleTable::new();
            table.register_well_known(
                TEST_HANDLE,
                "node-signer",
                ALG_ECC_P256,
                PERM_SIGN | PERM_VERIFY | PERM_GET_PUBKEY,
            );

            // Cross-node principal: the calling node. Wildcard-allow for the
            // test; in production the cert subject is the principal and IAM is
            // per-node, per-op.
            let iam = IamPolicy::parse(
                "version: 1\nstatements:\n  - principals: [\"*\"]\n    handles: [\"*\"]\n    ops: [\"*\"]\n",
            )
            .unwrap();
            let caller = CallerId {
                peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                vm_id: "node-b".to_string(),
                cert_thumbprint: [0u8; 32],
            };

            let (mut stream, _) = listener.accept().unwrap();
            // Serve sequentially until the client hangs up (read_request errors).
            while let Ok(req) = read_request(&mut stream) {
                let (resp, _) = handle_request(&req, &caller, &mut table, &iam, &hsm);
                if write_response(&mut stream, &resp).is_err() {
                    break;
                }
            }
            // `tmp` stays alive for the whole connection — dropping it here
            // removes the keystore only after the client is done.
            drop(tmp);
        });
        addr
    }

    #[test]
    fn client_signs_and_verifies_against_real_daemon() {
        let addr = spawn_test_daemon();
        let mut client = VhsmClient::new(TcpStream::connect(addr).unwrap());

        // GetRandom returns exactly the requested count.
        let rnd = client.get_random(16).unwrap();
        assert_eq!(rnd.len(), 16);

        // Sign, then verify the SAME message — a real crypto round-trip
        // through the daemon proves the framing is byte-exact end to end.
        let msg = b"cross-node attestation challenge";
        let sig = client.sign(TEST_HANDLE, msg).unwrap();
        assert!(!sig.is_empty(), "signature must be non-empty");
        assert!(
            client.verify(TEST_HANDLE, msg, &sig).unwrap(),
            "daemon must verify its own signature"
        );

        // A signature over a DIFFERENT message must NOT verify — and that's an
        // Ok(false), not an Err.
        assert!(
            !client.verify(TEST_HANDLE, b"tampered", &sig).unwrap(),
            "verify must reject a signature over a different message"
        );

        // GetPubkey returns a DER SubjectPublicKeyInfo (SEQUENCE, 0x30).
        let spki = client.get_pubkey(TEST_HANDLE).unwrap();
        assert_eq!(spki[0], 0x30, "SPKI DER starts with a SEQUENCE tag");
    }

    #[test]
    fn client_surfaces_invalid_handle_as_status_error() {
        let addr = spawn_test_daemon();
        let mut client = VhsmClient::new(TcpStream::connect(addr).unwrap());

        // 0x0003 isn't registered in the handle table → InvalidHandle.
        let err = client.sign(0x0003, b"x").unwrap_err();
        assert!(
            matches!(err, ClientError::Status(StatusCode::InvalidHandle)),
            "expected Status(InvalidHandle), got {err:?}"
        );
    }
}
