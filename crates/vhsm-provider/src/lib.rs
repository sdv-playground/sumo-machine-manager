//! vHSM-backed [`HsmCryptoProvider`] for the guest.
//!
//! The guest-side implementation of the shared handle-addressed HSM-crypto
//! contract: it holds a connected [`VhsmClient`] and forwards each op over the
//! vHSM wire to the host `vhsm-ssd` (which performs the crypto against the real
//! key material — sim or hardware — and returns the result). Same interface the
//! host satisfies with `SimHsm`/HSE, so callers (the onboard minter, the
//! gateway authorizer, the updater) are backend-agnostic.
//!
//! `KeyHandle` (the slot number) bridges straight to the wire `handle: u32` via
//! [`KeyHandle::get`].
//!
//! ## What's NOT bridged
//!
//! Ops without a single guest-facing wire op return `NotSupported`:
//! - `derive` — `KeyDerive` is host-only on the wire.
//! - `generate_key` — the wire `KeyGenerate` *allocates* a handle, whereas the
//!   contract method targets a caller-chosen handle (semantic mismatch).
//! - `generate_csr`, `get_trust_anchor_der` — no wire op.
//! - `unwrap_cek_a128kw` / `unwrap_cek_ecdh_es` — the guest CEK-unwrap (the
//!   updater's encrypted-payload install, where `device-decrypt` is ECDH-ES)
//!   needs a NEW server-side `UnwrapCek` wire op; see the crate TODO.

use std::sync::Mutex;

use hsm_contract::{HsmCryptoProvider, HsmError, KeyHandle, KeyType, SlotInfo, SlotKind};
pub use vhsm_client::OwnedTransport;
use vhsm_client::{ClientError, Transport, VhsmClient};

/// A guest HSM-crypto provider backed by a connected vHSM wire client.
///
/// The client needs `&mut` per call but the contract is `&self`, so the client
/// is behind a `Mutex` (the daemon serves a connection sequentially anyway).
pub struct VhsmProvider<T: Transport> {
    client: Mutex<VhsmClient<T>>,
}

impl<T: Transport> VhsmProvider<T> {
    /// Wrap an already-connected wire client.
    pub fn new(client: VhsmClient<T>) -> Self {
        Self {
            client: Mutex::new(client),
        }
    }
}

impl VhsmProvider<OwnedTransport> {
    /// Connect via the OS-native privileged path (QNX `/dev/vhsm` devctl, Linux
    /// AF_UNIX to the local daemon, else `$VHSM_HOST` TCP).
    pub fn connect_local() -> Result<Self, ClientError> {
        Ok(Self::new(VhsmClient::connect_local()?))
    }

    /// Connect over TCP to an explicit `host:port`.
    pub fn connect(addr: &str) -> Result<Self, ClientError> {
        Ok(Self::new(VhsmClient::connect(addr)?))
    }
}

/// Map a wire-client error onto the contract's [`HsmError`].
fn map_err(e: ClientError) -> HsmError {
    use vhsm_client::ClientError as C;
    use vhsm_proto::StatusCode;
    match e {
        C::Status(StatusCode::InvalidHandle) => {
            HsmError::KeyNotFound("vHSM: invalid handle".into())
        }
        C::Status(StatusCode::CryptoError) => HsmError::CryptoError("vHSM crypto error".into()),
        C::Io(io) => HsmError::CryptoError(format!("vHSM transport: {io}")),
        other => HsmError::CryptoError(format!("vHSM: {other}")),
    }
}

/// Map a wire `ALG_*` algorithm id onto the contract's [`KeyType`].
fn key_type_for_alg(alg: u32) -> KeyType {
    match alg {
        vhsm_proto::ALG_AES_128 => KeyType::Aes128,
        vhsm_proto::ALG_AES_256 => KeyType::Aes256,
        vhsm_proto::ALG_HMAC_SHA256 => KeyType::HmacSha256,
        vhsm_proto::ALG_ED25519 => KeyType::Ed25519,
        // ECC-P256 and anything unrecognised default to the dominant EC slot type.
        _ => KeyType::EcP256,
    }
}

/// The `key_id` alias for a handle — the registry name for well-known slots, or
/// the deterministic `dyn-{handle}` name SimHsm uses for dynamic keys.
fn key_id_for_handle(handle: u32) -> String {
    vhsm_proto::slot_for_handle(handle)
        .map(|s| s.key_id.to_string())
        .unwrap_or_else(|| format!("dyn-{handle:08x}"))
}

impl<T: Transport + Send> HsmCryptoProvider for VhsmProvider<T> {
    fn sign(&self, handle: KeyHandle, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        self.client
            .lock()
            .unwrap()
            .sign(handle.get(), data)
            .map_err(map_err)
    }

    fn sign_raw_p256(&self, handle: KeyHandle, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        // The wire `Sign` returns DER; COSE_Sign1 / JWS ES256 want raw 64-byte
        // r||s — convert here so the bridge satisfies the contract's contract.
        let der = self
            .client
            .lock()
            .unwrap()
            .sign(handle.get(), data)
            .map_err(map_err)?;
        let sig = p256::ecdsa::Signature::from_der(&der)
            .map_err(|e| HsmError::CryptoError(format!("vHSM sign: bad DER signature: {e}")))?;
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(&self, handle: KeyHandle, data: &[u8], signature: &[u8]) -> Result<bool, HsmError> {
        self.client
            .lock()
            .unwrap()
            .verify(handle.get(), data, signature)
            .map_err(map_err)
    }

    fn encrypt(&self, handle: KeyHandle, plaintext: &[u8]) -> Result<Vec<u8>, HsmError> {
        self.client
            .lock()
            .unwrap()
            .encrypt(handle.get(), plaintext)
            .map_err(map_err)
    }

    fn decrypt(&self, handle: KeyHandle, ciphertext: &[u8]) -> Result<Vec<u8>, HsmError> {
        self.client
            .lock()
            .unwrap()
            .decrypt(handle.get(), ciphertext)
            .map_err(map_err)
    }

    fn mac_generate(&self, handle: KeyHandle, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        self.client
            .lock()
            .unwrap()
            .mac_generate(handle.get(), data)
            .map_err(map_err)
    }

    fn mac_verify(&self, handle: KeyHandle, data: &[u8], mac: &[u8]) -> Result<bool, HsmError> {
        self.client
            .lock()
            .unwrap()
            .mac_verify(handle.get(), mac, data)
            .map_err(map_err)
    }

    fn derive(
        &self,
        _handle: KeyHandle,
        _context: &[u8],
        _len: usize,
    ) -> Result<Vec<u8>, HsmError> {
        // `KeyDerive` is a host-only wire op — not exposed to guests.
        Err(HsmError::NotSupported("derive over the vHSM wire".into()))
    }

    fn random(&self, len: usize) -> Result<Vec<u8>, HsmError> {
        self.client.lock().unwrap().get_random(len).map_err(map_err)
    }

    fn get_certificate_der(&self, handle: KeyHandle) -> Result<Vec<u8>, HsmError> {
        self.client
            .lock()
            .unwrap()
            .get_cert(handle.get())
            .map_err(map_err)
    }

    fn get_public_key_der(&self, handle: KeyHandle) -> Result<Vec<u8>, HsmError> {
        self.client
            .lock()
            .unwrap()
            .get_pubkey(handle.get())
            .map_err(map_err)
    }

    fn get_slot_info(&self, handle: KeyHandle) -> Result<SlotInfo, HsmError> {
        let info = self
            .client
            .lock()
            .unwrap()
            .get_handle_info(handle.get())
            .map_err(map_err)?;
        // The guest wire only ever exposes key slots (the monotonic-counter slot
        // is host-only, never guest-registered), but map ALG_MONOTONIC honestly
        // anyway rather than defaulting it to a key type.
        let kind = if info.algorithm == vhsm_proto::ALG_MONOTONIC {
            SlotKind::Monotonic
        } else {
            SlotKind::Key(key_type_for_alg(info.algorithm))
        };
        Ok(SlotInfo {
            handle: KeyHandle(info.handle),
            key_id: key_id_for_handle(info.handle),
            kind,
            // The wire's GetHandleInfo doesn't report cert presence; callers
            // that need the cert call get_certificate_der directly.
            has_certificate: false,
            allowed_guests: None,
            allowed_ops: None,
        })
    }

    // sign_raw_p256 overridden above. generate_key / generate_csr /
    // get_trust_anchor_der / unwrap_cek_a128kw / unwrap_cek_ecdh_es keep the
    // trait's NotSupported defaults — see the crate doc.
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
    use p256::pkcs8::EncodePublicKey;
    use vhsm_proto::{Op, Response, StatusCode};

    const JWT_SIGNING: u32 = vhsm_proto::HANDLE_JWT_SIGNING;

    /// A mock transport standing in for vhsm-ssd: it signs with a fixed P-256
    /// key (the daemon hashes SHA-256 internally, which `SigningKey::sign`
    /// mirrors), serves its SPKI for GetPubkey, and zero-fills GetRandom.
    struct MockDaemon {
        key: SigningKey,
        bad_handle: u32,
    }

    impl Transport for MockDaemon {
        fn request(
            &mut self,
            op: u32,
            session_id: u32,
            payload: &[u8],
        ) -> std::io::Result<Response> {
            // Every op here carries a leading 4-byte handle.
            let handle = u32::from_le_bytes(payload[0..4].try_into().unwrap());
            if handle == self.bad_handle {
                return Ok(Response {
                    op,
                    session_id,
                    status: StatusCode::InvalidHandle as u32,
                    payload: vec![],
                });
            }
            let ok = |payload| {
                Ok(Response {
                    op,
                    session_id,
                    status: StatusCode::Ok as u32,
                    payload,
                })
            };
            match Op::from_u32(op) {
                Some(Op::Sign) => {
                    let message = &payload[4..];
                    let sig: Signature = self.key.sign(message);
                    ok(sig.to_der().as_bytes().to_vec())
                }
                Some(Op::GetPubkey) => {
                    let spki = self
                        .key
                        .verifying_key()
                        .to_public_key_der()
                        .unwrap()
                        .as_bytes()
                        .to_vec();
                    let mut out = (spki.len() as u32).to_le_bytes().to_vec();
                    out.extend_from_slice(&spki);
                    ok(out)
                }
                Some(Op::GetRandom) => {
                    let n = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
                    Ok(Response {
                        op,
                        session_id,
                        status: StatusCode::Ok as u32,
                        payload: vec![0u8; n],
                    })
                }
                _ => Ok(Response {
                    op,
                    session_id,
                    status: StatusCode::InvalidParam as u32,
                    payload: vec![],
                }),
            }
        }
    }

    fn provider_with_key(key: SigningKey) -> VhsmProvider<MockDaemon> {
        VhsmProvider::new(VhsmClient::new(MockDaemon {
            key,
            bad_handle: 0xDEAD,
        }))
    }

    #[test]
    fn random_forwards_count() {
        let p = provider_with_key(SigningKey::random(&mut rand::thread_rng()));
        assert_eq!(p.random(24).unwrap().len(), 24);
    }

    #[test]
    fn invalid_handle_maps_to_key_not_found() {
        let p = provider_with_key(SigningKey::random(&mut rand::thread_rng()));
        let err = p.sign(KeyHandle(0xDEAD), b"x").unwrap_err();
        assert!(matches!(err, HsmError::KeyNotFound(_)), "got {err:?}");
    }

    /// The contract round-trip: `sign_raw_p256` must yield a valid ES256 (raw
    /// r||s) signature over the message — exactly what a `TieredAuthorizer`
    /// reconstructs and verifies for a JWT. Proves the DER->raw bridge.
    #[test]
    fn sign_raw_p256_yields_verifiable_es256() {
        let key = SigningKey::random(&mut rand::thread_rng());
        let vk: VerifyingKey = *key.verifying_key();
        let p = provider_with_key(key);

        let message = b"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJvbmJvYXJkIn0";
        let raw = p.sign_raw_p256(KeyHandle(JWT_SIGNING), message).unwrap();
        assert_eq!(raw.len(), 64, "ES256 raw signature is r||s = 64 bytes");

        // Reconstruct from the raw form and verify (SHA-256 done internally) —
        // the same operation the SOVD authorizer performs on a bearer JWT.
        let sig = Signature::from_slice(&raw).unwrap();
        use p256::ecdsa::signature::Verifier;
        assert!(
            vk.verify(message, &sig).is_ok(),
            "raw r||s must verify against the signing key's public half"
        );
    }

    #[test]
    fn get_public_key_der_returns_spki() {
        let key = SigningKey::random(&mut rand::thread_rng());
        let p = provider_with_key(key);
        let spki = p.get_public_key_der(KeyHandle(JWT_SIGNING)).unwrap();
        assert_eq!(spki[0], 0x30, "SPKI DER starts with a SEQUENCE tag");
    }

    #[test]
    fn unsupported_ops_decline() {
        let p = provider_with_key(SigningKey::random(&mut rand::thread_rng()));
        assert!(matches!(
            p.derive(KeyHandle(JWT_SIGNING), b"ctx", 16).unwrap_err(),
            HsmError::NotSupported(_)
        ));
        assert!(matches!(
            p.unwrap_cek_a128kw(KeyHandle(JWT_SIGNING), b"wrapped")
                .unwrap_err(),
            HsmError::NotSupported(_)
        ));
        assert!(matches!(
            p.generate_csr(KeyHandle(JWT_SIGNING), "cn").unwrap_err(),
            HsmError::NotSupported(_)
        ));
    }
}
