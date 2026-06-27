//! # Link-B — the host ↔ physical-HSE service protocol
//!
//! Link B is the contract between the host HSM proxy (`vhsm-ssd`) and the
//! backend HSM **service** — software (the sim) or a vendor's C HSE service.
//! It is the *only* thing a hardware/HSE vendor implements. It is deliberately
//! **decoupled** from the guest-facing vHSM wire (`vhsm-proto`, "link A"): link A
//! evolves for guests, link B evolves for backends, and neither breaks the other.
//! See `docs/design/hsm-backend-architecture.md`.
//!
//! ## What link B carries
//!
//! The full backend surface — every `HsmCryptoProvider` crypto op plus the
//! provisioning / key-management ops — addressed by **logical handle**. It does
//! NOT carry sessions, guest identity, IAM, or the handshake (those are link A,
//! terminated by the proxy), nor the service lifecycle (`start`/`stop`/`status`,
//! which is the proxy *spawning* the backend, not an op sent to it).
//!
//! ## Wire frame (uniform 3-field little-endian header, both directions)
//!
//! ```text
//!   request:   op:u32     | flags:u32 | payload_len:u32 | payload[payload_len]
//!   response:  status:u32 | flags:u32 | result_len:u32  | result[result_len]
//! ```
//!
//! `flags` is reserved (`FLAGS_NONE`) — header room to evolve without a breaking
//! change. On an error response `status != ST_OK` and `result` is a UTF-8
//! message (`ST_ROLLBACK_REJECTED` carries the version-conflict text).
//!
//! ## Field encoding within a payload
//!
//! Three primitives (see [`Writer`] / [`Reader`]):
//! - `u8` / `u32` / `u64` — fixed little-endian scalars.
//! - **bytes** — a length-prefixed blob (`len:u32 | bytes[len]`); use when a
//!   variable field is followed by more fields.
//! - **tail** — the rest of the payload, no length prefix; the LAST (or only)
//!   variable field.
//!
//! ## Op payloads (the frozen contract)
//!
//! | op | request payload | response result |
//! |----|-----------------|-----------------|
//! | `SIGN` | handle:u32, data:tail | signature (DER) |
//! | `SIGN_RAW_P256` | handle:u32, data:tail | 64-byte r‖s |
//! | `VERIFY` | handle:u32, data:bytes, signature:tail | u8 (0/1) |
//! | `ENCRYPT` | handle:u32, plaintext:tail | iv‖ct‖tag |
//! | `DECRYPT` | handle:u32, ciphertext:tail | plaintext |
//! | `MAC_GENERATE` | handle:u32, data:tail | 16-byte tag |
//! | `MAC_VERIFY` | handle:u32, data:bytes, mac:tail | u8 (0/1) |
//! | `DERIVE` | handle:u32, out_len:u32, context:tail | derived bytes |
//! | `RANDOM` | len:u32 | random bytes |
//! | `GET_CERTIFICATE_DER` | handle:u32 | DER |
//! | `GET_PUBLIC_KEY_DER` | handle:u32 | SPKI DER |
//! | `GET_TRUST_ANCHOR_DER` | anchor_id:tail (utf-8) | DER |
//! | `GET_KEY_INFO` | handle:u32 | KeyInfo (below) |
//! | `GENERATE_KEY` | handle:u32, alg:u32 | pubkey DER (empty for symmetric) |
//! | `GENERATE_CSR` | handle:u32, subject_cn:tail (utf-8) | CSR DER |
//! | `UNWRAP_CEK_A128KW` | handle:u32, wrapped_cek:tail | 16-byte CEK |
//! | `UNWRAP_CEK_ECDH_ES` | handle:u32, ephem_pub:bytes, wrapped_cek:bytes, recipient_protected:tail | 16-byte CEK |
//! | `IS_PROVISIONED` | — | u8 (0/1) |
//! | `PROVISION` | suit_envelope:tail | — |
//! | `LIST_KEYS` | — | count:u32, KeyInfo* |
//! | `PROVISIONING_STATE` | — | state:u32 |
//! | `ARM_ENROLLMENT` | ttl_present:u8, ttl:u64, vm_id:tail (utf-8) | — |
//! | `IS_ENROLLED` | vm_id:tail (utf-8) | u8 (0/1) |
//! | `CLEAR_ENROLLED` | vm_id:tail (utf-8) | u8 (0/1) |
//! | `GET_PUBLIC_KEY` | role:u32 | COSE_Key CBOR |
//!
//! `KeyInfo` = `handle:u32, key_type:u32, has_certificate:u8, key_id:bytes(utf-8),
//! allowed_guests:optlist, allowed_ops:optlist`, where
//! `optlist = present:u8, [count:u32, item:bytes(utf-8) × count]` (present=0 ⇒ None).
//! `key_type` is one of the `KEYTYPE_*` constants below.

use std::io::{self, Read, Write};

/// Reserved flags value (header room for forward-compat).
pub const FLAGS_NONE: u32 = 0;

/// Frame header size: three little-endian `u32` fields.
pub const HEADER_SIZE: usize = 12;

// ── Op codes — crypto (0x01..0x1F) ───────────────────────────────────────────
pub const OP_SIGN: u32 = 0x01;
pub const OP_SIGN_RAW_P256: u32 = 0x02;
pub const OP_VERIFY: u32 = 0x03;
pub const OP_ENCRYPT: u32 = 0x04;
pub const OP_DECRYPT: u32 = 0x05;
pub const OP_MAC_GENERATE: u32 = 0x06;
pub const OP_MAC_VERIFY: u32 = 0x07;
pub const OP_DERIVE: u32 = 0x08;
pub const OP_RANDOM: u32 = 0x09;
pub const OP_GET_CERTIFICATE_DER: u32 = 0x0A;
pub const OP_GET_PUBLIC_KEY_DER: u32 = 0x0B;
pub const OP_GET_TRUST_ANCHOR_DER: u32 = 0x0C;
pub const OP_GET_KEY_INFO: u32 = 0x0D;
pub const OP_GENERATE_KEY: u32 = 0x0E;
pub const OP_GENERATE_CSR: u32 = 0x0F;
pub const OP_UNWRAP_CEK_A128KW: u32 = 0x10;
pub const OP_UNWRAP_CEK_ECDH_ES: u32 = 0x11;

// ── Op codes — provisioning / key management (0x20..0x3F) ─────────────────────
pub const OP_IS_PROVISIONED: u32 = 0x20;
pub const OP_PROVISION: u32 = 0x21;
pub const OP_LIST_KEYS: u32 = 0x22;
pub const OP_PROVISIONING_STATE: u32 = 0x23;
pub const OP_ARM_ENROLLMENT: u32 = 0x24;
pub const OP_IS_ENROLLED: u32 = 0x25;
pub const OP_CLEAR_ENROLLED: u32 = 0x26;
pub const OP_GET_PUBLIC_KEY: u32 = 0x27;

// ── Status codes (mirror the HsmError categories) ─────────────────────────────
pub const ST_OK: u32 = 0;
pub const ST_NOT_PROVISIONED: u32 = 1;
pub const ST_ALREADY_PROVISIONED: u32 = 2;
pub const ST_NOT_RUNNING: u32 = 3;
pub const ST_ALREADY_RUNNING: u32 = 4;
pub const ST_KEYSTORE_ERROR: u32 = 5;
pub const ST_PROCESS_ERROR: u32 = 6;
pub const ST_CONFIG_ERROR: u32 = 7;
pub const ST_ENVELOPE_INVALID: u32 = 8;
pub const ST_PAYLOAD_INVALID: u32 = 9;
pub const ST_DECRYPTION_FAILED: u32 = 10;
pub const ST_ROLLBACK_REJECTED: u32 = 11;
pub const ST_NOT_SUPPORTED: u32 = 12;
pub const ST_CRYPTO_ERROR: u32 = 13;
pub const ST_KEY_NOT_FOUND: u32 = 14;
/// Malformed frame / payload didn't match the op's layout.
pub const ST_PROTOCOL_ERROR: u32 = 15;

// ── KeyType wire constants — `KeyInfo.key_type` (GET_KEY_INFO / LIST_KEYS) ─────
pub const KEYTYPE_EC_P256: u32 = 1;
pub const KEYTYPE_ED25519: u32 = 2;
pub const KEYTYPE_AES128: u32 = 3;
pub const KEYTYPE_AES256: u32 = 4;
pub const KEYTYPE_HMAC_SHA256: u32 = 5;

/// A decode error: the payload didn't match the op's expected layout.
#[derive(Debug, PartialEq, Eq)]
pub struct ProtoError(pub &'static str);

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "link-b protocol error: {}", self.0)
    }
}
impl std::error::Error for ProtoError {}

// ── Frame I/O ────────────────────────────────────────────────────────────────

/// Read one frame: `(a, flags, payload)` where `a` is the op (request) or the
/// status (response).
pub fn read_frame(r: &mut impl Read) -> io::Result<(u32, u32, Vec<u8>)> {
    let mut hdr = [0u8; HEADER_SIZE];
    r.read_exact(&mut hdr)?;
    let a = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
    let flags = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
    let len = u32::from_le_bytes(hdr[8..12].try_into().unwrap()) as usize;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok((a, flags, payload))
}

/// Write one frame with `a` = op (request) or status (response).
pub fn write_frame(w: &mut impl Write, a: u32, flags: u32, payload: &[u8]) -> io::Result<()> {
    let mut buf = Vec::with_capacity(HEADER_SIZE + payload.len());
    buf.extend_from_slice(&a.to_le_bytes());
    buf.extend_from_slice(&flags.to_le_bytes());
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload);
    w.write_all(&buf)?;
    w.flush()
}

// ── Payload field primitives ─────────────────────────────────────────────────

/// Builds a payload from fields. `bytes` is length-prefixed; `tail` is the
/// final unprefixed field. Mirror of [`Reader`].
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn u8(mut self, v: u8) -> Self {
        self.buf.push(v);
        self
    }
    pub fn u32(mut self, v: u32) -> Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u64(mut self, v: u64) -> Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    /// A length-prefixed blob (`len:u32 | bytes`).
    pub fn bytes(mut self, b: &[u8]) -> Self {
        self.buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(b);
        self
    }
    /// The final field: the rest of the payload, no length prefix.
    pub fn tail(mut self, b: &[u8]) -> Self {
        self.buf.extend_from_slice(b);
        self
    }
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Reads fields from a payload, mirroring [`Writer`].
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(ProtoError("length overflow"))?;
        let s = self
            .buf
            .get(self.pos..end)
            .ok_or(ProtoError("short payload"))?;
        self.pos = end;
        Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8, ProtoError> {
        Ok(self.take(1)?[0])
    }
    pub fn u32(&mut self) -> Result<u32, ProtoError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64, ProtoError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    /// A length-prefixed blob written by [`Writer::bytes`].
    pub fn bytes(&mut self) -> Result<&'a [u8], ProtoError> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    /// The rest of the payload (the [`Writer::tail`] field).
    pub fn tail(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trips_both_directions() {
        let mut buf = Vec::new();
        write_frame(&mut buf, OP_SIGN, FLAGS_NONE, b"hello").unwrap();
        let (op, flags, payload) = read_frame(&mut &buf[..]).unwrap();
        assert_eq!(
            (op, flags, payload.as_slice()),
            (OP_SIGN, FLAGS_NONE, b"hello".as_slice())
        );

        let mut rbuf = Vec::new();
        write_frame(&mut rbuf, ST_OK, FLAGS_NONE, &[1]).unwrap();
        let (status, _f, result) = read_frame(&mut &rbuf[..]).unwrap();
        assert_eq!((status, result.as_slice()), (ST_OK, [1].as_slice()));
    }

    #[test]
    fn writer_reader_round_trip() {
        // A representative multi-field payload: verify(handle, data:bytes, sig:tail).
        let payload = Writer::new()
            .u32(0x0006)
            .bytes(b"the message")
            .tail(b"the-signature")
            .finish();
        let mut r = Reader::new(&payload);
        assert_eq!(r.u32().unwrap(), 0x0006);
        assert_eq!(r.bytes().unwrap(), b"the message");
        assert_eq!(r.tail(), b"the-signature");
    }

    #[test]
    fn reader_rejects_short_payload() {
        let mut r = Reader::new(&[0u8; 2]);
        assert_eq!(r.u32(), Err(ProtoError("short payload")));
    }

    #[test]
    fn op_spaces_are_disjoint_crypto_below_provisioning() {
        assert!(OP_UNWRAP_CEK_ECDH_ES < 0x20, "crypto ops live below 0x20");
        assert!(
            OP_IS_PROVISIONED >= 0x20,
            "provisioning ops live at/above 0x20"
        );
        assert_ne!(ST_OK, ST_NOT_SUPPORTED);
    }
}
