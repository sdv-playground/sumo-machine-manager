//! Link-B bridge — `HsmCryptoProvider` over the out-of-process link-B service.
//!
//! Stage 1 of making the HSM backend a uniform out-of-process **link-B**
//! service (see `crates/hsm-link-b` for the frozen wire contract and
//! `docs/hsm-backend-architecture.md`). This module is the Rust glue on
//! both ends of that wire:
//!
//! - [`LinkBClient`] implements [`HsmCryptoProvider`] by encoding each op per
//!   the frozen payload table, sending it over a `UnixStream`, and decoding the
//!   response. It is what the host proxy uses to reach the backend.
//! - [`serve_crypto`] is the inverse harness: it reads frames off a stream,
//!   dispatches each crypto op to a concrete [`HsmCryptoProvider`] backend, and
//!   writes the response back. It is what a (software or vendor) backend runs.
//!
//! Only the crypto ops (`OP_*` `< 0x20`) are wired in this stage; provisioning /
//! key-management ops (`>= 0x20`) answer `ST_NOT_SUPPORTED` for now.
//!
//! The [`KeyInfo`] struct and the `HsmError <-> status` mapping are encoded here
//! (the `hsm-link-b` crate is intentionally dep-free and carries only the
//! frame codec + numeric constants).

use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Mutex;

use hsm_link_b::*;

use crate::{HsmCryptoProvider, HsmError, KeyHandle, KeyInfo, KeyType};

// ── HsmError <-> status mapping ───────────────────────────────────────────────

/// Map an [`HsmError`] to its link-B `ST_*` status code.
///
/// `RollbackRejected` has no dedicated category on either side except
/// `ST_ROLLBACK_REJECTED`; it carries its conflict text as the message.
pub fn status_from_error(e: &HsmError) -> u32 {
    match e {
        HsmError::NotProvisioned => ST_NOT_PROVISIONED,
        HsmError::AlreadyProvisioned => ST_ALREADY_PROVISIONED,
        HsmError::NotRunning => ST_NOT_RUNNING,
        HsmError::AlreadyRunning => ST_ALREADY_RUNNING,
        HsmError::KeystoreError(_) => ST_KEYSTORE_ERROR,
        HsmError::ProcessError(_) => ST_PROCESS_ERROR,
        HsmError::ConfigError(_) => ST_CONFIG_ERROR,
        HsmError::EnvelopeInvalid(_) => ST_ENVELOPE_INVALID,
        HsmError::PayloadInvalid(_) => ST_PAYLOAD_INVALID,
        HsmError::DecryptionFailed(_) => ST_DECRYPTION_FAILED,
        HsmError::RollbackRejected { .. } => ST_ROLLBACK_REJECTED,
        HsmError::NotSupported(_) => ST_NOT_SUPPORTED,
        HsmError::CryptoError(_) => ST_CRYPTO_ERROR,
        HsmError::KeyNotFound(_) => ST_KEY_NOT_FOUND,
    }
}

/// Reconstruct an [`HsmError`] from a link-B status + error message bytes.
///
/// Inverse of [`status_from_error`] for every variant except `RollbackRejected`,
/// which collapses to `CryptoError(message)` — lossy, but the rollback path is
/// provisioning-only and never travels the crypto wire decoded here. An unknown
/// status is surfaced verbatim rather than silently swallowed.
pub fn status_to_error(status: u32, result: &[u8]) -> HsmError {
    let msg = String::from_utf8_lossy(result).into_owned();
    match status {
        ST_NOT_PROVISIONED => HsmError::NotProvisioned,
        ST_ALREADY_PROVISIONED => HsmError::AlreadyProvisioned,
        ST_NOT_RUNNING => HsmError::NotRunning,
        ST_ALREADY_RUNNING => HsmError::AlreadyRunning,
        ST_KEYSTORE_ERROR => HsmError::KeystoreError(msg),
        ST_PROCESS_ERROR => HsmError::ProcessError(msg),
        ST_CONFIG_ERROR => HsmError::ConfigError(msg),
        ST_ENVELOPE_INVALID => HsmError::EnvelopeInvalid(msg),
        ST_PAYLOAD_INVALID => HsmError::PayloadInvalid(msg),
        ST_DECRYPTION_FAILED => HsmError::DecryptionFailed(msg),
        ST_ROLLBACK_REJECTED => HsmError::CryptoError(msg),
        ST_NOT_SUPPORTED => HsmError::NotSupported(msg),
        ST_CRYPTO_ERROR => HsmError::CryptoError(msg),
        ST_KEY_NOT_FOUND => HsmError::KeyNotFound(msg),
        _ => HsmError::CryptoError(format!("link-b status {status}: {msg}")),
    }
}

/// The error-response result bytes for `e`: the inner message for the
/// String-carrying variants, the Display text for `RollbackRejected`, empty for
/// the unit variants (their status code is self-describing). Inverse of the
/// message half of [`status_to_error`].
fn error_message_bytes(e: &HsmError) -> Vec<u8> {
    match e {
        HsmError::KeystoreError(s)
        | HsmError::ProcessError(s)
        | HsmError::ConfigError(s)
        | HsmError::EnvelopeInvalid(s)
        | HsmError::PayloadInvalid(s)
        | HsmError::DecryptionFailed(s)
        | HsmError::NotSupported(s)
        | HsmError::CryptoError(s)
        | HsmError::KeyNotFound(s) => s.as_bytes().to_vec(),
        HsmError::RollbackRejected { .. } => e.to_string().into_bytes(),
        HsmError::NotProvisioned
        | HsmError::AlreadyProvisioned
        | HsmError::NotRunning
        | HsmError::AlreadyRunning => Vec::new(),
    }
}

// ── KeyType <-> KEYTYPE_* mapping ─────────────────────────────────────────────

fn keytype_to_wire(kt: KeyType) -> u32 {
    match kt {
        KeyType::EcP256 => KEYTYPE_EC_P256,
        KeyType::Ed25519 => KEYTYPE_ED25519,
        KeyType::Aes128 => KEYTYPE_AES128,
        KeyType::Aes256 => KEYTYPE_AES256,
        KeyType::HmacSha256 => KEYTYPE_HMAC_SHA256,
    }
}

fn keytype_from_wire(v: u32) -> Result<KeyType, HsmError> {
    match v {
        KEYTYPE_EC_P256 => Ok(KeyType::EcP256),
        KEYTYPE_ED25519 => Ok(KeyType::Ed25519),
        KEYTYPE_AES128 => Ok(KeyType::Aes128),
        KEYTYPE_AES256 => Ok(KeyType::Aes256),
        KEYTYPE_HMAC_SHA256 => Ok(KeyType::HmacSha256),
        other => Err(HsmError::CryptoError(format!(
            "link-b: unknown key_type {other}"
        ))),
    }
}

// ── KeyInfo codec ─────────────────────────────────────────────────────────────

/// Encode a [`KeyInfo`] per the frozen layout:
/// `handle:u32, key_type:u32, has_certificate:u8, key_id:bytes,
/// allowed_guests:optlist, allowed_ops:optlist`.
pub fn encode_key_info(ki: &KeyInfo) -> Vec<u8> {
    let mut w = Writer::new()
        .u32(ki.handle.get())
        .u32(keytype_to_wire(ki.key_type))
        .u8(ki.has_certificate as u8)
        .bytes(ki.key_id.as_bytes());
    w = write_optlist(w, ki.allowed_guests.as_deref());
    w = write_optlist(w, ki.allowed_ops.as_deref());
    w.finish()
}

/// Decode a [`KeyInfo`] written by [`encode_key_info`].
pub fn decode_key_info(buf: &[u8]) -> Result<KeyInfo, HsmError> {
    let mut r = Reader::new(buf);
    let handle = KeyHandle(r.u32().map_err(proto_err)?);
    let key_type = keytype_from_wire(r.u32().map_err(proto_err)?)?;
    let has_certificate = r.u8().map_err(proto_err)? != 0;
    let key_id = String::from_utf8_lossy(r.bytes().map_err(proto_err)?).into_owned();
    let allowed_guests = read_optlist(&mut r)?;
    let allowed_ops = read_optlist(&mut r)?;
    Ok(KeyInfo {
        handle,
        key_id,
        key_type,
        has_certificate,
        allowed_guests,
        allowed_ops,
    })
}

/// `optlist = present:u8, [count:u32, item:bytes × count]` (present=0 ⇒ None).
fn write_optlist(w: Writer, list: Option<&[String]>) -> Writer {
    match list {
        None => w.u8(0),
        Some(items) => {
            let mut w = w.u8(1).u32(items.len() as u32);
            for item in items {
                w = w.bytes(item.as_bytes());
            }
            w
        }
    }
}

fn read_optlist(r: &mut Reader<'_>) -> Result<Option<Vec<String>>, HsmError> {
    if r.u8().map_err(proto_err)? == 0 {
        return Ok(None);
    }
    let count = r.u32().map_err(proto_err)? as usize;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        items.push(String::from_utf8_lossy(r.bytes().map_err(proto_err)?).into_owned());
    }
    Ok(Some(items))
}

fn proto_err(e: ProtoError) -> HsmError {
    HsmError::CryptoError(format!("link-b decode: {e}"))
}

// ── Client: HsmCryptoProvider over a link-B stream ────────────────────────────

/// A link-B client: forwards every [`HsmCryptoProvider`] op over a `UnixStream`
/// to a backend running [`serve_crypto`]. The stream is mutex-guarded so the
/// request/response exchange is atomic across concurrent callers.
pub struct LinkBClient {
    stream: Mutex<UnixStream>,
}

impl LinkBClient {
    /// Connect to a link-B service listening on the Unix socket at `path`.
    pub fn connect(path: &Path) -> io::Result<Self> {
        Ok(Self {
            stream: Mutex::new(UnixStream::connect(path)?),
        })
    }

    /// Wrap an already-connected stream (e.g. one accepted/dialed elsewhere).
    pub fn from_stream(stream: UnixStream) -> Self {
        Self {
            stream: Mutex::new(stream),
        }
    }

    /// Send one op + payload, read the response; map a non-`ST_OK` status back
    /// to an [`HsmError`].
    fn call(&self, op: u32, payload: Vec<u8>) -> Result<Vec<u8>, HsmError> {
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| HsmError::ProcessError("link-b stream mutex poisoned".into()))?;
        write_frame(&mut *stream, op, FLAGS_NONE, &payload)
            .map_err(|e| HsmError::ProcessError(format!("link-b write: {e}")))?;
        let (status, _flags, result) = read_frame(&mut *stream)
            .map_err(|e| HsmError::ProcessError(format!("link-b read: {e}")))?;
        if status == ST_OK {
            Ok(result)
        } else {
            Err(status_to_error(status, &result))
        }
    }
}

impl HsmCryptoProvider for LinkBClient {
    fn sign(&self, handle: KeyHandle, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        self.call(OP_SIGN, Writer::new().u32(handle.get()).tail(data).finish())
    }

    fn sign_raw_p256(&self, handle: KeyHandle, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        self.call(
            OP_SIGN_RAW_P256,
            Writer::new().u32(handle.get()).tail(data).finish(),
        )
    }

    fn verify(&self, handle: KeyHandle, data: &[u8], signature: &[u8]) -> Result<bool, HsmError> {
        let result = self.call(
            OP_VERIFY,
            Writer::new()
                .u32(handle.get())
                .bytes(data)
                .tail(signature)
                .finish(),
        )?;
        Ok(result.first() == Some(&1))
    }

    fn encrypt(&self, handle: KeyHandle, plaintext: &[u8]) -> Result<Vec<u8>, HsmError> {
        self.call(
            OP_ENCRYPT,
            Writer::new().u32(handle.get()).tail(plaintext).finish(),
        )
    }

    fn decrypt(&self, handle: KeyHandle, ciphertext: &[u8]) -> Result<Vec<u8>, HsmError> {
        self.call(
            OP_DECRYPT,
            Writer::new().u32(handle.get()).tail(ciphertext).finish(),
        )
    }

    fn mac_generate(&self, handle: KeyHandle, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        self.call(
            OP_MAC_GENERATE,
            Writer::new().u32(handle.get()).tail(data).finish(),
        )
    }

    fn mac_verify(&self, handle: KeyHandle, data: &[u8], mac: &[u8]) -> Result<bool, HsmError> {
        let result = self.call(
            OP_MAC_VERIFY,
            Writer::new()
                .u32(handle.get())
                .bytes(data)
                .tail(mac)
                .finish(),
        )?;
        Ok(result.first() == Some(&1))
    }

    fn derive(&self, handle: KeyHandle, context: &[u8], len: usize) -> Result<Vec<u8>, HsmError> {
        self.call(
            OP_DERIVE,
            Writer::new()
                .u32(handle.get())
                .u32(len as u32)
                .tail(context)
                .finish(),
        )
    }

    fn random(&self, len: usize) -> Result<Vec<u8>, HsmError> {
        self.call(OP_RANDOM, Writer::new().u32(len as u32).finish())
    }

    fn get_certificate_der(&self, handle: KeyHandle) -> Result<Vec<u8>, HsmError> {
        self.call(
            OP_GET_CERTIFICATE_DER,
            Writer::new().u32(handle.get()).finish(),
        )
    }

    fn get_public_key_der(&self, handle: KeyHandle) -> Result<Vec<u8>, HsmError> {
        self.call(
            OP_GET_PUBLIC_KEY_DER,
            Writer::new().u32(handle.get()).finish(),
        )
    }

    fn get_trust_anchor_der(&self, anchor_id: &str) -> Result<Vec<u8>, HsmError> {
        self.call(
            OP_GET_TRUST_ANCHOR_DER,
            Writer::new().tail(anchor_id.as_bytes()).finish(),
        )
    }

    fn get_key_info(&self, handle: KeyHandle) -> Result<KeyInfo, HsmError> {
        let result = self.call(OP_GET_KEY_INFO, Writer::new().u32(handle.get()).finish())?;
        decode_key_info(&result)
    }

    fn generate_key(&self, handle: KeyHandle, alg: u32) -> Result<Vec<u8>, HsmError> {
        self.call(
            OP_GENERATE_KEY,
            Writer::new().u32(handle.get()).u32(alg).finish(),
        )
    }

    fn generate_csr(&self, handle: KeyHandle, subject_cn: &str) -> Result<Vec<u8>, HsmError> {
        self.call(
            OP_GENERATE_CSR,
            Writer::new()
                .u32(handle.get())
                .tail(subject_cn.as_bytes())
                .finish(),
        )
    }

    fn unwrap_cek_a128kw(
        &self,
        handle: KeyHandle,
        wrapped_cek: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        self.call(
            OP_UNWRAP_CEK_A128KW,
            Writer::new().u32(handle.get()).tail(wrapped_cek).finish(),
        )
    }

    fn unwrap_cek_ecdh_es(
        &self,
        handle: KeyHandle,
        ephem_pub: &[u8],
        wrapped_cek: &[u8],
        recipient_protected: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        self.call(
            OP_UNWRAP_CEK_ECDH_ES,
            Writer::new()
                .u32(handle.get())
                .bytes(ephem_pub)
                .bytes(wrapped_cek)
                .tail(recipient_protected)
                .finish(),
        )
    }
}

// ── Service: serve a backend over a link-B stream ─────────────────────────────

/// Serve link-B crypto ops from `stream` against `backend` until the peer
/// closes the connection (read EOF), at which point this returns cleanly.
///
/// Only crypto ops (`< 0x20`) are dispatched in Stage 1; provisioning ops and
/// unknown ops answer `ST_NOT_SUPPORTED`. A request whose payload doesn't match
/// the op's layout answers `ST_PROTOCOL_ERROR`.
pub fn serve_crypto(mut stream: UnixStream, backend: &dyn HsmCryptoProvider) {
    // Read frames until the peer drops (clean EOF) or a transport error.
    while let Ok((op, _flags, payload)) = read_frame(&mut stream) {
        let (status, result) = match run_crypto_op(op, &payload, backend) {
            Ok(Ok(result)) => (ST_OK, result),
            Ok(Err(e)) => (status_from_error(&e), error_message_bytes(&e)),
            Err(proto) => (ST_PROTOCOL_ERROR, proto.0.as_bytes().to_vec()),
        };
        if write_frame(&mut stream, status, FLAGS_NONE, &result).is_err() {
            break;
        }
    }
}

/// Decode one crypto request, run it on `backend`, and encode the result.
///
/// The outer `Err(ProtoError)` means the payload didn't match the op layout
/// (→ `ST_PROTOCOL_ERROR`); the inner `Err(HsmError)` is the backend's own
/// rejection (→ [`status_from_error`]). A non-crypto / unknown op yields an
/// inner `NotSupported` (→ `ST_NOT_SUPPORTED`).
fn run_crypto_op(
    op: u32,
    payload: &[u8],
    backend: &dyn HsmCryptoProvider,
) -> Result<Result<Vec<u8>, HsmError>, ProtoError> {
    let mut r = Reader::new(payload);
    let out: Result<Vec<u8>, HsmError> = match op {
        OP_SIGN => backend.sign(KeyHandle(r.u32()?), r.tail()),
        OP_SIGN_RAW_P256 => backend.sign_raw_p256(KeyHandle(r.u32()?), r.tail()),
        OP_VERIFY => {
            let handle = KeyHandle(r.u32()?);
            let data = r.bytes()?;
            backend
                .verify(handle, data, r.tail())
                .map(|b| vec![b as u8])
        }
        OP_ENCRYPT => backend.encrypt(KeyHandle(r.u32()?), r.tail()),
        OP_DECRYPT => backend.decrypt(KeyHandle(r.u32()?), r.tail()),
        OP_MAC_GENERATE => backend.mac_generate(KeyHandle(r.u32()?), r.tail()),
        OP_MAC_VERIFY => {
            let handle = KeyHandle(r.u32()?);
            let data = r.bytes()?;
            backend
                .mac_verify(handle, data, r.tail())
                .map(|b| vec![b as u8])
        }
        OP_DERIVE => {
            let handle = KeyHandle(r.u32()?);
            let out_len = r.u32()? as usize;
            backend.derive(handle, r.tail(), out_len)
        }
        OP_RANDOM => backend.random(r.u32()? as usize),
        OP_GET_CERTIFICATE_DER => backend.get_certificate_der(KeyHandle(r.u32()?)),
        OP_GET_PUBLIC_KEY_DER => backend.get_public_key_der(KeyHandle(r.u32()?)),
        OP_GET_TRUST_ANCHOR_DER => {
            let anchor_id = String::from_utf8_lossy(r.tail()).into_owned();
            backend.get_trust_anchor_der(&anchor_id)
        }
        OP_GET_KEY_INFO => backend
            .get_key_info(KeyHandle(r.u32()?))
            .map(|ki| encode_key_info(&ki)),
        OP_GENERATE_KEY => {
            let handle = KeyHandle(r.u32()?);
            let alg = r.u32()?;
            backend.generate_key(handle, alg)
        }
        OP_GENERATE_CSR => {
            let handle = KeyHandle(r.u32()?);
            let subject_cn = String::from_utf8_lossy(r.tail()).into_owned();
            backend.generate_csr(handle, &subject_cn)
        }
        OP_UNWRAP_CEK_A128KW => backend.unwrap_cek_a128kw(KeyHandle(r.u32()?), r.tail()),
        OP_UNWRAP_CEK_ECDH_ES => {
            let handle = KeyHandle(r.u32()?);
            let ephem_pub = r.bytes()?;
            let wrapped_cek = r.bytes()?;
            backend.unwrap_cek_ecdh_es(handle, ephem_pub, wrapped_cek, r.tail())
        }
        // Provisioning ops (>= 0x20) and unknown ops are not wired in Stage 1.
        _ => return Ok(Err(HsmError::NotSupported(format!("link-b op {op:#06x}")))),
    };
    Ok(out)
}

// ── e2e round-trip test ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::thread;

    /// A backend whose every op returns a recognizable, deterministic value.
    /// Where an op carries multiple/variable request fields (the bools, the
    /// length-parametric ops, the multi-byte-field ops, string args), the
    /// return value is derived from the inputs so a correct round-trip proves
    /// the *request* framing too — not just the response.
    struct TestCrypto;

    impl HsmCryptoProvider for TestCrypto {
        fn sign(&self, _handle: KeyHandle, _data: &[u8]) -> Result<Vec<u8>, HsmError> {
            Ok(vec![0xAB; 64])
        }
        fn sign_raw_p256(&self, _handle: KeyHandle, _data: &[u8]) -> Result<Vec<u8>, HsmError> {
            Ok(vec![0xCD; 64])
        }
        fn verify(
            &self,
            handle: KeyHandle,
            data: &[u8],
            signature: &[u8],
        ) -> Result<bool, HsmError> {
            // Only the agreed inputs verify true → proves u32|bytes|tail framing.
            Ok(handle == KeyHandle(0x11) && data == b"verify-data" && signature == b"verify-sig")
        }
        fn encrypt(&self, _handle: KeyHandle, _plaintext: &[u8]) -> Result<Vec<u8>, HsmError> {
            Ok(b"IVCTTAG".to_vec())
        }
        fn decrypt(&self, _handle: KeyHandle, _ciphertext: &[u8]) -> Result<Vec<u8>, HsmError> {
            Ok(b"PLAINTEXT".to_vec())
        }
        fn mac_generate(&self, _handle: KeyHandle, _data: &[u8]) -> Result<Vec<u8>, HsmError> {
            Ok(vec![0x11; 16])
        }
        fn mac_verify(
            &self,
            _handle: KeyHandle,
            _data: &[u8],
            _mac: &[u8],
        ) -> Result<bool, HsmError> {
            // Return false to prove the 0/false bool round-trips too.
            Ok(false)
        }
        fn derive(
            &self,
            _handle: KeyHandle,
            context: &[u8],
            len: usize,
        ) -> Result<Vec<u8>, HsmError> {
            // Output depends on context (tail) and len (u32) → proves both.
            let mut out = context.to_vec();
            out.resize(len, 0xDE);
            Ok(out)
        }
        fn random(&self, len: usize) -> Result<Vec<u8>, HsmError> {
            Ok(vec![0xAA; len])
        }
        fn get_certificate_der(&self, handle: KeyHandle) -> Result<Vec<u8>, HsmError> {
            // Echo the handle → proves the u32 handle crossed for single-field ops.
            Ok(format!("cert:{}", handle.get()).into_bytes())
        }
        fn get_public_key_der(&self, _handle: KeyHandle) -> Result<Vec<u8>, HsmError> {
            Ok(b"PUBKEY".to_vec())
        }
        fn get_trust_anchor_der(&self, anchor_id: &str) -> Result<Vec<u8>, HsmError> {
            Ok(format!("anchor:{anchor_id}").into_bytes())
        }
        fn get_key_info(&self, _handle: KeyHandle) -> Result<KeyInfo, HsmError> {
            // A fixed KeyInfo with its OWN handle (distinct from the request) →
            // proves the KeyInfo struct encodes/decodes independently.
            Ok(KeyInfo {
                handle: KeyHandle(0x42),
                key_id: "test-key".to_string(),
                key_type: KeyType::EcP256,
                has_certificate: true,
                allowed_guests: Some(vec!["g1".to_string()]),
                allowed_ops: None,
            })
        }
        fn generate_key(&self, _handle: KeyHandle, alg: u32) -> Result<Vec<u8>, HsmError> {
            // Echo alg → proves the second u32 (not the handle) crossed.
            Ok(format!("genkey:alg={alg}").into_bytes())
        }
        fn generate_csr(&self, _handle: KeyHandle, subject_cn: &str) -> Result<Vec<u8>, HsmError> {
            Ok(format!("csr:{subject_cn}").into_bytes())
        }
        fn unwrap_cek_a128kw(
            &self,
            _handle: KeyHandle,
            wrapped_cek: &[u8],
        ) -> Result<Vec<u8>, HsmError> {
            let mut out = b"a128kw:".to_vec();
            out.extend_from_slice(wrapped_cek);
            Ok(out)
        }
        fn unwrap_cek_ecdh_es(
            &self,
            _handle: KeyHandle,
            ephem_pub: &[u8],
            wrapped_cek: &[u8],
            recipient_protected: &[u8],
        ) -> Result<Vec<u8>, HsmError> {
            // Concatenate all three byte args → proves bytes|bytes|tail framing.
            Ok([ephem_pub, wrapped_cek, recipient_protected].concat())
        }
    }

    #[test]
    fn link_b_round_trips_every_crypto_op() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("link-b.sock");

        let listener = UnixListener::bind(&sock).unwrap();
        let server = thread::spawn(move || {
            let (stream, _addr) = listener.accept().unwrap();
            serve_crypto(stream, &TestCrypto);
        });

        let client = LinkBClient::connect(&sock).unwrap();

        // 1. sign
        assert_eq!(
            client.sign(KeyHandle(0x01), b"msg").unwrap(),
            vec![0xAB; 64]
        );
        // 2. sign_raw_p256
        assert_eq!(
            client.sign_raw_p256(KeyHandle(0x02), b"msg").unwrap(),
            vec![0xCD; 64]
        );
        // 3. verify — true (agreed inputs) and false (wrong signature)
        assert!(client
            .verify(KeyHandle(0x11), b"verify-data", b"verify-sig")
            .unwrap());
        assert!(!client
            .verify(KeyHandle(0x11), b"verify-data", b"WRONG")
            .unwrap());
        // 4. encrypt
        assert_eq!(
            client.encrypt(KeyHandle(0x03), b"pt").unwrap(),
            b"IVCTTAG".to_vec()
        );
        // 5. decrypt
        assert_eq!(
            client.decrypt(KeyHandle(0x04), b"ct").unwrap(),
            b"PLAINTEXT".to_vec()
        );
        // 6. mac_generate
        assert_eq!(
            client.mac_generate(KeyHandle(0x05), b"d").unwrap(),
            vec![0x11; 16]
        );
        // 7. mac_verify — false round-trips
        assert!(!client.mac_verify(KeyHandle(0x06), b"d", b"mac").unwrap());
        // 8. derive — context ++ pad-to-len
        let derived = client.derive(KeyHandle(0x07), b"ctx", 8).unwrap();
        let mut expect = b"ctx".to_vec();
        expect.resize(8, 0xDE);
        assert_eq!(derived, expect);
        // 9. random — exactly `len` bytes
        assert_eq!(client.random(20).unwrap(), vec![0xAA; 20]);
        // 10. get_certificate_der — handle echoed (0x29 == 41)
        assert_eq!(
            client.get_certificate_der(KeyHandle(0x29)).unwrap(),
            b"cert:41".to_vec()
        );
        // 11. get_public_key_der
        assert_eq!(
            client.get_public_key_der(KeyHandle(0x0B)).unwrap(),
            b"PUBKEY".to_vec()
        );
        // 12. get_trust_anchor_der — string arg echoed
        assert_eq!(
            client.get_trust_anchor_der("delegation-root").unwrap(),
            b"anchor:delegation-root".to_vec()
        );
        // 13. get_key_info — full struct round-trips (incl. optlists)
        let ki = client.get_key_info(KeyHandle(0x99)).unwrap();
        assert_eq!(ki.handle, KeyHandle(0x42));
        assert_eq!(ki.key_id, "test-key");
        assert_eq!(ki.key_type, KeyType::EcP256);
        assert!(ki.has_certificate);
        assert_eq!(ki.allowed_guests, Some(vec!["g1".to_string()]));
        assert_eq!(ki.allowed_ops, None);
        // 14. generate_key — alg echoed (0x21 == 33)
        assert_eq!(
            client.generate_key(KeyHandle(0x0E), 0x21).unwrap(),
            b"genkey:alg=33".to_vec()
        );
        // 15. generate_csr — subject echoed
        assert_eq!(
            client.generate_csr(KeyHandle(0x0F), "CN=device").unwrap(),
            b"csr:CN=device".to_vec()
        );
        // 16. unwrap_cek_a128kw — wrapped CEK echoed
        assert_eq!(
            client
                .unwrap_cek_a128kw(KeyHandle(0x10), b"wrapped")
                .unwrap(),
            b"a128kw:wrapped".to_vec()
        );
        // 17. unwrap_cek_ecdh_es — all three byte fields concatenated
        assert_eq!(
            client
                .unwrap_cek_ecdh_es(KeyHandle(0x11), b"ephem", b"wrapped", b"protected")
                .unwrap(),
            b"ephemwrappedprotected".to_vec()
        );

        // Drop the client → server's read hits EOF → serve_crypto returns.
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn key_info_codec_round_trips_with_none_and_some_optlists() {
        let ki = KeyInfo {
            handle: KeyHandle(0x1234),
            key_id: "alias".to_string(),
            key_type: KeyType::Aes256,
            has_certificate: false,
            allowed_guests: None,
            allowed_ops: Some(vec!["sign".to_string(), "verify".to_string()]),
        };
        let decoded = decode_key_info(&encode_key_info(&ki)).unwrap();
        assert_eq!(decoded.handle, ki.handle);
        assert_eq!(decoded.key_id, ki.key_id);
        assert_eq!(decoded.key_type, ki.key_type);
        assert_eq!(decoded.has_certificate, ki.has_certificate);
        assert_eq!(decoded.allowed_guests, None);
        assert_eq!(
            decoded.allowed_ops,
            Some(vec!["sign".to_string(), "verify".to_string()])
        );
    }

    #[test]
    fn status_error_mapping_is_inverse() {
        // Unit variant.
        assert_eq!(
            status_from_error(&HsmError::NotProvisioned),
            ST_NOT_PROVISIONED
        );
        assert!(matches!(
            status_to_error(ST_NOT_PROVISIONED, b""),
            HsmError::NotProvisioned
        ));
        // String-carrying variant: message survives the round-trip.
        let e = HsmError::KeyNotFound("0x06".into());
        let st = status_from_error(&e);
        let back = status_to_error(st, &error_message_bytes(&e));
        assert!(matches!(back, HsmError::KeyNotFound(s) if s == "0x06"));
        // Unknown status surfaces verbatim.
        assert!(matches!(
            status_to_error(9999, b"boom"),
            HsmError::CryptoError(s) if s == "link-b status 9999: boom"
        ));
    }
}
