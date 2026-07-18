//! CWT cert contract for the v3 ENROLL/handshake (protocol.md §11).
//!
//! The guest presents a CWT (RFC 8392) COSE_Sign1 cert whose claim set and
//! `cnf` key layout are fixed by the protocol. These labels and the audience
//! string are the **single source of truth** for both sides of that contract:
//! the daemon's verifier (`vhsm-ssd::cert`) and any offboard minter (e.g. the
//! provisioning CLI's pre-mint path) import them from here — never redefine
//! them locally, or the two ends drift apart undetected.
//!
//! Not part of the frozen byte-wire (`vhsm_proto.h` / `c_header_freeze`):
//! the CWT rides *inside* wire payloads as CBOR, so its labels live in this
//! companion module rather than the header snapshot.

/// The single audience accepted by the daemon (`aud` claim). Different
/// vhsm-ssd instances across a fleet could use distinct audiences (e.g.,
/// per-region shards); v1 hard-codes the single value.
pub const VHSM_AUDIENCE: &str = "vhsm-ssd";

/// CWT claim labels (RFC 8392 §3.1.1).
pub const CLAIM_ISS: i64 = 1;
pub const CLAIM_SUB: i64 = 2;
pub const CLAIM_AUD: i64 = 3;
pub const CLAIM_EXP: i64 = 4;
pub const CLAIM_NBF: i64 = 5;
pub const CLAIM_IAT: i64 = 6;
pub const CLAIM_CTI: i64 = 7;
/// RFC 8747 §3.1: confirmation method, "cnf".
pub const CLAIM_CNF: i64 = -65537;

/// COSE_Key labels for the pubkey inside `cnf` (RFC 8152 §7).
pub const COSE_KEY_KTY: i64 = 1;
pub const COSE_KEY_ALG: i64 = 3;
pub const COSE_KEY_EC2_CRV: i64 = -1;
pub const COSE_KEY_EC2_X: i64 = -2;
pub const COSE_KEY_EC2_Y: i64 = -3;
/// `kty` value for EC2 keys (RFC 8152 §13).
pub const KTY_EC2: i64 = 2;
