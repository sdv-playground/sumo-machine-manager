//! The v3 vHSM wire client.
//!
//! One client for every caller of the vHSM wire protocol — the host cross-node
//! path (a caller-supplied mTLS `Read + Write` stream) and the in-guest path
//! (TCP, AF_UNIX, or the QNX `/dev/vhsm` devctl). The wire framing
//! ([`vhsm_proto`]) is identical across carriers; only the carrier differs,
//! abstracted behind the [`Transport`] trait.
//!
//! Keys are addressed by their numeric `handle` (the slot number from the
//! [`vhsm_proto`] registry). This crate is the WIRE layer — it depends only on
//! `vhsm_proto`, never `hsm-contract`; the typed `KeyHandle` /
//! `HsmCryptoProvider` bridge lives one layer up in `vhsm-provider`.
//!
//! ## Identity
//!
//! Crypto ops carry no in-band credential: the daemon authorises by the
//! connection's established identity — source IP on the private bridge,
//! SO_PEERCRED on the UDS, caller uid on devctl, or the mTLS client cert on the
//! cross-node path. The optional `guest-auth` feature adds the in-band v3 CWT
//! handshake (HELLO/AUTH/ENROLL) the guest vhsm-daemons run on their upstream
//! connection — see [`auth`].
//!
//! `session_id` is a client-side correlation counter, not a security token; the
//! daemon echoes it and the client checks it to catch a framing desync.

use std::io::{self, Read, Write};

use vhsm_proto::codec::{read_response, write_request};
use vhsm_proto::{Op, Request, Response, StatusCode};

#[cfg(feature = "guest-auth")]
pub mod auth;

#[cfg(target_os = "nto")]
mod transport_devctl;
#[cfg(target_os = "nto")]
pub use transport_devctl::{DevctlTransport, DEFAULT_DEVCTL_PATH};

/// Default `host:port` when `VHSM_HOST` is unset — the local vHSM endpoint.
pub const DEFAULT_VHSM_HOST: &str = "127.0.0.1:5100";

/// Default AF_UNIX path the local guest vhsm-daemon listens on.
#[cfg(unix)]
pub const DEFAULT_UDS_PATH: &str = "/run/sumo/vhsm.sock";

/// An error from a vHSM client call.
#[derive(Debug)]
pub enum ClientError {
    /// Transport-level failure (connection closed, short read/write, devctl errno).
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

/// A carrier for the vHSM wire protocol: one request in, one response out.
///
/// Implemented for any `Read + Write` stream (TCP, AF_UNIX, an mTLS stream) via
/// the blanket impl below, and directly by [`DevctlTransport`] on QNX (where a
/// request is a `devctl` syscall, not a byte stream).
pub trait Transport {
    /// Send one framed request and return the parsed response.
    fn request(&mut self, op: u32, session_id: u32, payload: &[u8]) -> io::Result<Response>;
}

impl<S: Read + Write> Transport for S {
    fn request(&mut self, op: u32, session_id: u32, payload: &[u8]) -> io::Result<Response> {
        let req = Request {
            op,
            session_id,
            payload: payload.to_vec(),
        };
        write_request(self, &req)?;
        read_response(self)
    }
}

/// Parsed handle metadata from [`VhsmClient::get_handle_info`].
#[derive(Debug, Clone)]
pub struct HandleInfo {
    pub handle: u32,
    pub algorithm: u32,
    pub permitted_ops: u32,
    pub persistent: bool,
    pub label: [u8; vhsm_proto::LABEL_LEN],
}

/// A transport chosen by the convenience constructors ([`VhsmClient::connect`],
/// [`VhsmClient::connect_local`], …). The cross-node path constructs
/// `VhsmClient::new(stream)` over a caller-supplied stream instead.
pub enum OwnedTransport {
    Tcp(std::net::TcpStream),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
    #[cfg(target_os = "nto")]
    Devctl(DevctlTransport),
}

impl Transport for OwnedTransport {
    fn request(&mut self, op: u32, session_id: u32, payload: &[u8]) -> io::Result<Response> {
        match self {
            OwnedTransport::Tcp(s) => s.request(op, session_id, payload),
            #[cfg(unix)]
            OwnedTransport::Unix(s) => s.request(op, session_id, payload),
            #[cfg(target_os = "nto")]
            OwnedTransport::Devctl(d) => d.request(op, session_id, payload),
        }
    }
}

/// A synchronous vHSM client over a single connected [`Transport`].
///
/// One request/response per op, strictly ordered — the daemon serves a
/// connection sequentially, so the client mirrors that.
pub struct VhsmClient<T> {
    transport: T,
    next_session: u32,
}

impl<T: Transport> VhsmClient<T> {
    /// Wrap a connected transport. For the cross-node path this is a stream that
    /// has already completed the mTLS handshake; for the in-guest path use the
    /// [`connect`](Self::connect) / [`connect_local`](Self::connect_local)
    /// constructors which build an [`OwnedTransport`].
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            next_session: 1,
        }
    }

    /// Consume the client and return the underlying transport.
    pub fn into_inner(self) -> T {
        self.transport
    }

    /// One request/response round-trip. Verifies the response's op and session
    /// id match the request so a framing desync fails loud.
    fn call(&mut self, op: Op, payload: Vec<u8>) -> Result<Vec<u8>> {
        let session_id = self.next_session;
        // Never reuse 0; wrap back to 1 so the id stays a tidy nonzero counter.
        self.next_session = self.next_session.wrapping_add(1).max(1);

        let resp = self.transport.request(op as u32, session_id, &payload)?;

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

    /// `GetRandom`: request `count` random bytes (daemon caps at `MAX_RANDOM`).
    pub fn get_random(&mut self, count: usize) -> Result<Vec<u8>> {
        self.call(Op::GetRandom, (count as u32).to_le_bytes().to_vec())
    }

    /// `Sign`: sign `message` with the key behind `handle`. Returns the DER
    /// `r || s` signature for P-256. The daemon hashes the message internally
    /// (SHA-256 for P-256) — pass the message, not a digest.
    pub fn sign(&mut self, handle: u32, message: &[u8]) -> Result<Vec<u8>> {
        let mut payload = handle.to_le_bytes().to_vec();
        payload.extend_from_slice(message);
        self.call(Op::Sign, payload)
    }

    /// `Verify`: check `signature` over `message` against the key behind
    /// `handle`. A cryptographic mismatch is `Ok(false)`, not `Err`; a missing
    /// handle or denied permission is `Err`.
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

    /// `Encrypt`: AES-GCM `plaintext` under the key behind `handle`. Returns
    /// `iv(12) || ciphertext || tag`.
    pub fn encrypt(&mut self, handle: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut payload = handle.to_le_bytes().to_vec();
        payload.extend_from_slice(plaintext);
        self.call(Op::Encrypt, payload)
    }

    /// `Decrypt`: inverse of [`encrypt`](Self::encrypt).
    pub fn decrypt(&mut self, handle: u32, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut payload = handle.to_le_bytes().to_vec();
        payload.extend_from_slice(ciphertext);
        self.call(Op::Decrypt, payload)
    }

    /// `MacGenerate`: AES-CMAC tag over `data` under the key behind `handle`.
    pub fn mac_generate(&mut self, handle: u32, data: &[u8]) -> Result<Vec<u8>> {
        let mut payload = handle.to_le_bytes().to_vec();
        payload.extend_from_slice(data);
        self.call(Op::MacGenerate, payload)
    }

    /// `MacVerify`: check `mac` over `data`. Like [`verify`](Self::verify), a
    /// cryptographic mismatch is `Ok(false)`.
    pub fn mac_verify(&mut self, handle: u32, mac: &[u8], data: &[u8]) -> Result<bool> {
        // payload: handle(4) + mac_len(4) + mac + data
        let mut payload = Vec::with_capacity(8 + mac.len() + data.len());
        payload.extend_from_slice(&handle.to_le_bytes());
        payload.extend_from_slice(&(mac.len() as u32).to_le_bytes());
        payload.extend_from_slice(mac);
        payload.extend_from_slice(data);
        match self.call(Op::MacVerify, payload) {
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

    /// `GetHandleInfo`: metadata (algorithm, permitted ops, label) for `handle`.
    pub fn get_handle_info(&mut self, handle: u32) -> Result<HandleInfo> {
        let resp = self.call(Op::GetHandleInfo, handle.to_le_bytes().to_vec())?;
        // Response: handle(4) algorithm(4) permitted_ops(4) persistent(1) pad(3) label(32) = 48
        if resp.len() < 48 {
            return Err(ClientError::Protocol(format!(
                "GetHandleInfo response too short: {} bytes",
                resp.len()
            )));
        }
        let mut label = [0u8; vhsm_proto::LABEL_LEN];
        label.copy_from_slice(&resp[16..16 + vhsm_proto::LABEL_LEN]);
        Ok(HandleInfo {
            handle: u32::from_le_bytes(resp[0..4].try_into().unwrap()),
            algorithm: u32::from_le_bytes(resp[4..8].try_into().unwrap()),
            permitted_ops: u32::from_le_bytes(resp[8..12].try_into().unwrap()),
            persistent: resp[12] != 0,
            label,
        })
    }

    /// `KeyGenerate`: allocate a fresh key. Returns `(handle, public_key_der)`;
    /// the pubkey is empty for symmetric algorithms. Note the daemon ALLOCATES
    /// the handle (dynamic range) and returns it — this is the wire's
    /// allocate-semantic, distinct from the handle-targeted
    /// `HsmCryptoProvider::generate_key`.
    pub fn key_generate(
        &mut self,
        algorithm: u32,
        permitted_ops: u32,
        persistent: bool,
        label: &str,
    ) -> Result<(u32, Vec<u8>)> {
        // payload: algorithm(4) permitted_ops(4) persistent(1) pad(3) label(32) = 44
        let mut payload = Vec::with_capacity(44);
        payload.extend_from_slice(&algorithm.to_le_bytes());
        payload.extend_from_slice(&permitted_ops.to_le_bytes());
        payload.push(if persistent { 1 } else { 0 });
        payload.extend_from_slice(&[0u8; 3]);
        let mut lbl = [0u8; vhsm_proto::LABEL_LEN];
        let bytes = label.as_bytes();
        let copy_len = bytes.len().min(vhsm_proto::LABEL_LEN);
        lbl[..copy_len].copy_from_slice(&bytes[..copy_len]);
        payload.extend_from_slice(&lbl);

        let resp = self.call(Op::KeyGenerate, payload)?;
        if resp.len() < 8 {
            return Err(ClientError::Protocol(format!(
                "KeyGenerate response too short: {} bytes",
                resp.len()
            )));
        }
        let handle = u32::from_le_bytes(resp[0..4].try_into().unwrap());
        let pubkey_len = u32::from_le_bytes(resp[4..8].try_into().unwrap()) as usize;
        let pubkey = resp.get(8..8 + pubkey_len).unwrap_or(&[]).to_vec();
        Ok((handle, pubkey))
    }

    /// Send a raw op code with a verbatim payload, returning the daemon's
    /// status + response payload without translating the status to a typed
    /// error. An escape hatch for diagnostics (host-only ops,
    /// malformed-payload probes).
    pub fn raw_request(&mut self, op: u32, payload: &[u8]) -> Result<(u32, Vec<u8>)> {
        let session_id = self.next_session;
        self.next_session = self.next_session.wrapping_add(1).max(1);
        let resp = self.transport.request(op, session_id, payload)?;
        Ok((resp.status, resp.payload))
    }
}

impl VhsmClient<OwnedTransport> {
    /// Connect via TCP to an explicit `host:port` (the unauthenticated bridge
    /// path; the daemon's policy is the gate).
    pub fn connect(addr: &str) -> Result<Self> {
        let stream = std::net::TcpStream::connect(addr)?;
        // Small request/response — latency matters. Best-effort.
        let _ = stream.set_nodelay(true);
        Ok(VhsmClient::new(OwnedTransport::Tcp(stream)))
    }

    /// Connect to the local guest vhsm-daemon over AF_UNIX (it SO_PEERCRED-gates
    /// each accept before forwarding upstream).
    #[cfg(unix)]
    pub fn connect_uds<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let stream = std::os::unix::net::UnixStream::connect(path)?;
        Ok(VhsmClient::new(OwnedTransport::Unix(stream)))
    }

    /// Connect via the OS-native privileged path: QNX `/dev/vhsm` devctl, Linux
    /// AF_UNIX to the local daemon (falling back to `$VHSM_HOST` TCP), or plain
    /// TCP elsewhere.
    pub fn connect_local() -> Result<Self> {
        #[cfg(target_os = "nto")]
        {
            let d = DevctlTransport::open(DEFAULT_DEVCTL_PATH)?;
            Ok(VhsmClient::new(OwnedTransport::Devctl(d)))
        }
        #[cfg(target_os = "linux")]
        {
            if let Ok(stream) = std::os::unix::net::UnixStream::connect(DEFAULT_UDS_PATH) {
                return Ok(VhsmClient::new(OwnedTransport::Unix(stream)));
            }
            Self::open()
        }
        #[cfg(not(any(target_os = "nto", target_os = "linux")))]
        {
            Self::open()
        }
    }

    /// Connect using `$VHSM_HOST` (falling back to [`DEFAULT_VHSM_HOST`]).
    /// Always TCP — use [`connect_local`](Self::connect_local) for the
    /// OS-native privileged path.
    pub fn open() -> Result<Self> {
        let addr = std::env::var("VHSM_HOST").unwrap_or_else(|_| DEFAULT_VHSM_HOST.to_string());
        Self::connect(&addr)
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
    use std::thread;

    use hsm::HsmCryptoProvider;
    use hsm_sim_backend::SimHsm;
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
    /// production — not a hand-rolled mock.
    fn spawn_test_daemon() -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let tmp = tempfile::tempdir().unwrap();
            let hsm = SimHsm::new(tmp.path().to_path_buf());
            HsmCryptoProvider::generate_key(&hsm, hsm::KeyHandle(TEST_HANDLE), ALG_ECC_P256)
                .unwrap();

            let mut table = HandleTable::new();
            table.register_well_known(
                TEST_HANDLE,
                "node-signer",
                ALG_ECC_P256,
                PERM_SIGN | PERM_VERIFY | PERM_GET_PUBKEY,
            );

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
            while let Ok(req) = read_request(&mut stream) {
                let (resp, _) = handle_request(&req, &caller, &mut table, &iam, &hsm);
                if write_response(&mut stream, &resp).is_err() {
                    break;
                }
            }
            drop(tmp);
        });
        addr
    }

    #[test]
    fn client_signs_and_verifies_against_real_daemon() {
        let addr = spawn_test_daemon();
        let mut client = VhsmClient::new(TcpStream::connect(addr).unwrap());

        let rnd = client.get_random(16).unwrap();
        assert_eq!(rnd.len(), 16);

        let msg = b"cross-node attestation challenge";
        let sig = client.sign(TEST_HANDLE, msg).unwrap();
        assert!(!sig.is_empty(), "signature must be non-empty");
        assert!(
            client.verify(TEST_HANDLE, msg, &sig).unwrap(),
            "daemon must verify its own signature"
        );
        assert!(
            !client.verify(TEST_HANDLE, b"tampered", &sig).unwrap(),
            "verify must reject a signature over a different message"
        );

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
