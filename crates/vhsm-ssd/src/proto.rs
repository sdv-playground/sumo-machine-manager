//! vHSM wire protocol types (v2) — matches `vhsm_proto.h` exactly.
//!
//! See `specs/vhsm/protocol.md` (VHSM-PROTO-002) for the full specification.

// ---- Magic and version --------------------------------------------------

pub const VHSM_MAGIC: [u8; 3] = [0x56, 0x48, 0x53]; // "VHS"
pub const VHSM_VERSION: u8 = 0x03;
pub const REQUEST_HEADER_SIZE: usize = 16;
pub const RESPONSE_HEADER_SIZE: usize = 20;

// ---- Limits -------------------------------------------------------------

pub const MAX_PAYLOAD: usize = 65536;
pub const MAX_RANDOM: usize = 1024;
pub const MAX_HANDLES: usize = 64;
pub const LABEL_LEN: usize = 32;

// ---- Transport ----------------------------------------------------------

pub const VHSM_PORT: u32 = 5100;

// ---- Operation codes (uint32) -------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum Op {
    // Guest-facing: crypto
    GetRandom = 0x0001,

    // Guest-facing: key management
    KeyGenerate = 0x0010,

    // Host-only: key management
    KeyImport = 0x0011,
    KeyDerive = 0x0012,
    KeyDelete = 0x0013,

    // Guest-facing: symmetric crypto
    Encrypt = 0x0020,
    Decrypt = 0x0021,

    // Guest-facing: MAC
    MacGenerate = 0x0030,
    MacVerify = 0x0031,

    // Guest-facing: asymmetric crypto
    Sign = 0x0040,
    Verify = 0x0041,

    // Guest-facing: queries
    GetHandleInfo = 0x0050,
    GetPubkey = 0x0051,
    GetCert = 0x0052,

    // Connection-handshake (v3 IAM identity layer, target). The
    // dispatcher does NOT route these through `handle_request` —
    // they're consumed inside the per-connection accept loop by
    // `auth.rs`. Listed here so codec parses them as valid op codes
    // and the audit log can name them. Not in `required_perm` /
    // `is_host_only` tables because they don't carry handles.
    Hello = 0x00F0,
    Auth = 0x00F1,
    AuthOk = 0x00F2,
    Enroll = 0x00F3,
    /// In-band enrolment: host pre-arms the vm_id via
    /// `HsmProvider::arm_enrollment`; guest sends just its CSR pubkey
    /// and the daemon resolves identity from the source IP. No
    /// bootstrap token bytes ever cross the wire. See §11.4-bis in the
    /// protocol spec.
    EnrollAssisted = 0x00F4,
}

impl Op {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0x0001 => Some(Op::GetRandom),
            0x0010 => Some(Op::KeyGenerate),
            0x0011 => Some(Op::KeyImport),
            0x0012 => Some(Op::KeyDerive),
            0x0013 => Some(Op::KeyDelete),
            0x0020 => Some(Op::Encrypt),
            0x0021 => Some(Op::Decrypt),
            0x0030 => Some(Op::MacGenerate),
            0x0031 => Some(Op::MacVerify),
            0x0040 => Some(Op::Sign),
            0x0041 => Some(Op::Verify),
            0x0050 => Some(Op::GetHandleInfo),
            0x0051 => Some(Op::GetPubkey),
            0x0052 => Some(Op::GetCert),
            0x00F0 => Some(Op::Hello),
            0x00F1 => Some(Op::Auth),
            0x00F2 => Some(Op::AuthOk),
            0x00F3 => Some(Op::Enroll),
            0x00F4 => Some(Op::EnrollAssisted),
            _ => None,
        }
    }

    /// True if this operation is host-only (rejected when the caller is a guest VM).
    pub fn is_host_only(self) -> bool {
        matches!(self, Op::KeyImport | Op::KeyDerive | Op::KeyDelete)
    }

    /// True if this is a connection-handshake op (HELLO / AUTH /
    /// AUTH_OK / ENROLL / ENROLL_ASSISTED). The handler dispatch
    /// table skips these — they're consumed by the accept-loop's
    /// auth state machine before any handle-bearing op can be
    /// dispatched.
    pub fn is_handshake(self) -> bool {
        matches!(
            self,
            Op::Hello | Op::Auth | Op::AuthOk | Op::Enroll | Op::EnrollAssisted
        )
    }

    /// Permission bit required for this operation, if applicable.
    pub fn required_perm(self) -> Option<u32> {
        match self {
            Op::Encrypt => Some(PERM_ENCRYPT),
            Op::Decrypt => Some(PERM_DECRYPT),
            Op::MacGenerate => Some(PERM_MAC_GEN),
            Op::MacVerify => Some(PERM_MAC_VFY),
            Op::Sign => Some(PERM_SIGN),
            Op::Verify => Some(PERM_VERIFY),
            Op::KeyDerive => Some(PERM_DERIVE),
            Op::KeyDelete => Some(PERM_DELETE),
            Op::GetPubkey => Some(PERM_GET_PUBKEY),
            Op::GetCert => Some(PERM_GET_CERT),
            Op::KeyGenerate => Some(PERM_KEY_GENERATE),
            Op::GetRandom | Op::GetHandleInfo | Op::KeyImport => None,
            // Handshake ops carry no handle and pre-date principal
            // resolution; they have their own authn check (the
            // proof-of-possession signature in AUTH, the
            // bootstrap-token comparison in ENROLL).
            Op::Hello | Op::Auth | Op::AuthOk | Op::Enroll | Op::EnrollAssisted => None,
        }
    }
}

// ---- Auth-failure reasons (uint16 in AUTH_FAIL payload) -----------------
//
// Returned by the daemon in the response payload of an AUTH-flow op
// when the client's HELLO/AUTH/ENROLL is refused. The status field
// of the response carries StatusCode::PolicyReject (for v3 auth-mode
// rejections) or StatusCode::InvalidParam (for malformed inputs);
// this enum is the structured "why."

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AuthFailReason {
    /// Cert signature didn't verify against iam-signing pubkey.
    BadCertSignature = 0x0001,
    /// Cert is past its `exp` or before its `nbf`.
    CertExpired = 0x0002,
    /// Cert `aud` is not `"vhsm-ssd"`.
    WrongAudience = 0x0003,
    /// Cert subject (principal name) not present in IAM policy.
    UnknownPrincipal = 0x0004,
    /// Proof-of-possession signature didn't verify against
    /// the cert's `cnf.pubkey`.
    BadProofSignature = 0x0005,
    /// ENROLL: bootstrap token didn't match the stored hash.
    BadBootstrapToken = 0x0006,
    /// ENROLL: bootstrap token was already consumed.
    TokenAlreadyConsumed = 0x0007,
    /// Client sent a v2-or-earlier request to a v3 daemon, or any
    /// other "wire version doesn't match what's required" condition.
    ProtocolTooOld = 0x0008,
    /// Generic malformed-input — short payloads, undecodable CWT
    /// CBOR, unknown opcode in handshake range, etc.
    InvalidParam = 0x0009,
}

impl AuthFailReason {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x0001 => Some(AuthFailReason::BadCertSignature),
            0x0002 => Some(AuthFailReason::CertExpired),
            0x0003 => Some(AuthFailReason::WrongAudience),
            0x0004 => Some(AuthFailReason::UnknownPrincipal),
            0x0005 => Some(AuthFailReason::BadProofSignature),
            0x0006 => Some(AuthFailReason::BadBootstrapToken),
            0x0007 => Some(AuthFailReason::TokenAlreadyConsumed),
            0x0008 => Some(AuthFailReason::ProtocolTooOld),
            0x0009 => Some(AuthFailReason::InvalidParam),
            _ => None,
        }
    }
}

// ---- Status codes (uint32) ----------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum StatusCode {
    Ok = 0x00000000,
    InvalidHandle = 0x00000001,
    PermissionDeny = 0x00000002,
    PolicyReject = 0x00000003,
    HseError = 0x00000004,
    InvalidParam = 0x00000005,
    NoResource = 0x00000006,
    StorageError = 0x00000007,
    CryptoError = 0x00000008,
    Internal = 0x00000009,
}

// ---- Algorithm identifiers (uint32) -------------------------------------

pub const ALG_AES_128: u32 = 0x0001;
pub const ALG_AES_256: u32 = 0x0002;
pub const ALG_HMAC_SHA256: u32 = 0x0010;
pub const ALG_ED25519: u32 = 0x0020;
pub const ALG_ECC_P256: u32 = 0x0021;

// ---- Permission bitmask (uint32) ----------------------------------------

pub const PERM_ENCRYPT: u32 = 1 << 0;
pub const PERM_DECRYPT: u32 = 1 << 1;
pub const PERM_MAC_GEN: u32 = 1 << 2;
pub const PERM_MAC_VFY: u32 = 1 << 3;
pub const PERM_SIGN: u32 = 1 << 4;
pub const PERM_VERIFY: u32 = 1 << 5;
pub const PERM_DERIVE: u32 = 1 << 6; // host-only
pub const PERM_DELETE: u32 = 1 << 7; // host-only
pub const PERM_GET_PUBKEY: u32 = 1 << 8;
pub const PERM_GET_CERT: u32 = 1 << 9;
pub const PERM_KEY_GENERATE: u32 = 1 << 10;

// ---- Well-known handles -------------------------------------------------
//
// Layout:
//   0x0000              HANDLE_INVALID
//   0x0001 .. 0x007F    sumo core well-known (this file owns numbering)
//   0x0080 .. 0x00FF    project extensions (downstream owns numbering; see
//                       guest-vm-spec/crates/vhsm-handles-ext and the C
//                       mirror at guest-vm-spec/shared/include/vhsm_proto.h)
//   0x0100 ..           dynamic, allocated by handle_table at runtime

pub const HANDLE_INVALID: u32 = 0x0000;
pub const HANDLE_SW_AUTHORITY: u32 = 0x0002;
pub const HANDLE_DEVICE_DECRYPT: u32 = 0x0003;
pub const HANDLE_IAM_SIGNING: u32 = 0x0004;
pub const HANDLE_KEY_AUTHORITY: u32 = 0x0005;
pub const HANDLE_JWT_SIGNING: u32 = 0x0006;
pub const HANDLE_STORAGE: u32 = 0x0007;
// SOVD token-issuer verify anchors (external authorities, pinned per
// tier). VERIFY + GET_PUBKEY; the matching private minters live offboard.
pub const HANDLE_OPERATIONAL_ISSUER: u32 = 0x0008;
pub const HANDLE_HIGH_CONSEQUENCE_ISSUER: u32 = 0x0009;

/// Lower boundary of the project-extension well-known range. Sumo owns
/// the slots strictly below this; downstream projects own
/// `HANDLE_PROJECT_BASE..HANDLE_DYNAMIC_BASE` for their own well-known
/// handles. Reserved here so sumo can renumber its core set without
/// stepping on downstream allocations.
pub const HANDLE_PROJECT_BASE: u32 = 0x0080;

pub const HANDLE_DYNAMIC_BASE: u32 = 0x0100;

/// Any reserved well-known handle (sumo core OR project extension).
/// Used by `HandleTable::register_well_known` to reject dynamic-range
/// inputs.
pub fn handle_is_well_known(h: u32) -> bool {
    (0x0001..HANDLE_DYNAMIC_BASE).contains(&h)
}

/// True if `h` is a sumo-owned well-known handle (strictly below the
/// project extension range).
pub fn handle_is_sumo_core(h: u32) -> bool {
    (0x0001..HANDLE_PROJECT_BASE).contains(&h)
}

/// True if `h` is in the project-extension range. Sumo does not know
/// the semantics of these handles — they are wired up by downstream
/// (e.g. guest-vm-spec's `vhsm-handles-ext`) and registered via the
/// same `register_well_known` API as the core set.
pub fn handle_is_project(h: u32) -> bool {
    (HANDLE_PROJECT_BASE..HANDLE_DYNAMIC_BASE).contains(&h)
}

// ---- Wire format structures ---------------------------------------------

/// Parsed request (after header decoding).
pub struct Request {
    pub op: u32,
    pub session_id: u32,
    pub payload: Vec<u8>,
}

/// Response to encode on the wire.
pub struct Response {
    pub op: u32,
    pub session_id: u32,
    pub status: u32,
    pub payload: Vec<u8>,
}

impl Response {
    pub fn ok(op: u32, session_id: u32, payload: Vec<u8>) -> Self {
        Self {
            op,
            session_id,
            status: StatusCode::Ok as u32,
            payload,
        }
    }

    pub fn err(op: u32, session_id: u32, status: StatusCode) -> Self {
        Self {
            op,
            session_id,
            status: status as u32,
            payload: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_from_u32_roundtrips_all_variants() {
        // Every variant must survive the u32 → Op → u32 round-trip.
        for op in [
            Op::GetRandom,
            Op::KeyGenerate,
            Op::KeyImport,
            Op::KeyDerive,
            Op::KeyDelete,
            Op::Encrypt,
            Op::Decrypt,
            Op::MacGenerate,
            Op::MacVerify,
            Op::Sign,
            Op::Verify,
            Op::GetHandleInfo,
            Op::GetPubkey,
            Op::GetCert,
            Op::Hello,
            Op::Auth,
            Op::AuthOk,
            Op::Enroll,
            Op::EnrollAssisted,
        ] {
            let v = op as u32;
            assert_eq!(Op::from_u32(v), Some(op), "op {op:?} (0x{v:04x})");
        }
    }

    #[test]
    fn op_is_handshake_matches_spec() {
        for op in [Op::Hello, Op::Auth, Op::AuthOk, Op::Enroll] {
            assert!(op.is_handshake(), "{op:?} should be handshake");
            assert!(!op.is_host_only(), "{op:?} is not host-only");
            assert_eq!(op.required_perm(), None, "{op:?} has no permission bit");
        }
        // None of the regular ops are handshake.
        for op in [
            Op::GetRandom,
            Op::KeyGenerate,
            Op::Encrypt,
            Op::Decrypt,
            Op::Sign,
            Op::Verify,
            Op::GetCert,
        ] {
            assert!(!op.is_handshake(), "{op:?} is not a handshake op");
        }
    }

    #[test]
    fn auth_fail_reason_roundtrips() {
        for r in [
            AuthFailReason::BadCertSignature,
            AuthFailReason::CertExpired,
            AuthFailReason::WrongAudience,
            AuthFailReason::UnknownPrincipal,
            AuthFailReason::BadProofSignature,
            AuthFailReason::BadBootstrapToken,
            AuthFailReason::TokenAlreadyConsumed,
            AuthFailReason::ProtocolTooOld,
            AuthFailReason::InvalidParam,
        ] {
            let v = r as u16;
            assert_eq!(AuthFailReason::from_u16(v), Some(r), "reason {r:?}");
        }
        assert_eq!(AuthFailReason::from_u16(0), None);
        assert_eq!(AuthFailReason::from_u16(0xFFFF), None);
    }

    #[test]
    fn op_from_u32_rejects_unknown() {
        assert_eq!(Op::from_u32(0x0000), None);
        assert_eq!(Op::from_u32(0xFFFF_FFFF), None);
        assert_eq!(Op::from_u32(0x0099), None);
    }

    #[test]
    fn op_is_host_only_matches_spec() {
        assert!(Op::KeyImport.is_host_only());
        assert!(Op::KeyDerive.is_host_only());
        assert!(Op::KeyDelete.is_host_only());
        // Everything else is guest-facing.
        for op in [
            Op::GetRandom,
            Op::KeyGenerate,
            Op::Encrypt,
            Op::Decrypt,
            Op::MacGenerate,
            Op::MacVerify,
            Op::Sign,
            Op::Verify,
            Op::GetHandleInfo,
            Op::GetPubkey,
            Op::GetCert,
            Op::Hello,
            Op::Auth,
            Op::AuthOk,
            Op::Enroll,
        ] {
            assert!(!op.is_host_only(), "{op:?} should be guest-facing");
        }
    }

    #[test]
    fn op_required_perm_maps_each_crypto_op_to_distinct_bit() {
        assert_eq!(Op::Encrypt.required_perm(), Some(PERM_ENCRYPT));
        assert_eq!(Op::Decrypt.required_perm(), Some(PERM_DECRYPT));
        assert_eq!(Op::MacGenerate.required_perm(), Some(PERM_MAC_GEN));
        assert_eq!(Op::MacVerify.required_perm(), Some(PERM_MAC_VFY));
        assert_eq!(Op::Sign.required_perm(), Some(PERM_SIGN));
        assert_eq!(Op::Verify.required_perm(), Some(PERM_VERIFY));
        assert_eq!(Op::KeyDerive.required_perm(), Some(PERM_DERIVE));
        assert_eq!(Op::KeyDelete.required_perm(), Some(PERM_DELETE));
        assert_eq!(Op::GetPubkey.required_perm(), Some(PERM_GET_PUBKEY));
        assert_eq!(Op::GetCert.required_perm(), Some(PERM_GET_CERT));
        assert_eq!(Op::KeyGenerate.required_perm(), Some(PERM_KEY_GENERATE));
        // No permission bit required for these
        assert_eq!(Op::GetRandom.required_perm(), None);
        assert_eq!(Op::GetHandleInfo.required_perm(), None);
        assert_eq!(Op::KeyImport.required_perm(), None);
    }

    #[test]
    fn permission_bits_are_all_distinct() {
        // Each permission bit must be unique — catches typos like duplicated shifts.
        let perms = [
            PERM_ENCRYPT,
            PERM_DECRYPT,
            PERM_MAC_GEN,
            PERM_MAC_VFY,
            PERM_SIGN,
            PERM_VERIFY,
            PERM_DERIVE,
            PERM_DELETE,
            PERM_GET_PUBKEY,
            PERM_GET_CERT,
            PERM_KEY_GENERATE,
        ];
        for (i, a) in perms.iter().enumerate() {
            // Each must be a power of two (single bit set)
            assert!(a.is_power_of_two(), "perm 0x{a:x} must be single bit");
            for b in &perms[i + 1..] {
                assert_eq!(a & b, 0, "perms 0x{a:x} and 0x{b:x} overlap");
            }
        }
    }

    #[test]
    fn well_known_handle_range_boundary() {
        assert!(!handle_is_well_known(HANDLE_INVALID));
        assert!(handle_is_well_known(HANDLE_SW_AUTHORITY));
        assert!(handle_is_well_known(HANDLE_STORAGE));
        assert!(handle_is_well_known(HANDLE_DYNAMIC_BASE - 1));
        assert!(!handle_is_well_known(HANDLE_DYNAMIC_BASE));
        assert!(!handle_is_well_known(HANDLE_DYNAMIC_BASE + 1));
        assert!(!handle_is_well_known(0xFFFF_FFFF));
    }

    #[test]
    fn sumo_core_does_not_overlap_project_range() {
        for &h in &[
            HANDLE_SW_AUTHORITY,
            HANDLE_DEVICE_DECRYPT,
            HANDLE_IAM_SIGNING,
            HANDLE_KEY_AUTHORITY,
            HANDLE_JWT_SIGNING,
            HANDLE_STORAGE,
            HANDLE_OPERATIONAL_ISSUER,
            HANDLE_HIGH_CONSEQUENCE_ISSUER,
        ] {
            assert!(handle_is_sumo_core(h), "0x{h:04x} should be sumo-core");
            assert!(
                !handle_is_project(h),
                "0x{h:04x} must not be in project range"
            );
        }
    }

    #[test]
    fn project_range_predicates_at_boundaries() {
        // Just below the project range
        assert!(handle_is_sumo_core(HANDLE_PROJECT_BASE - 1));
        assert!(!handle_is_project(HANDLE_PROJECT_BASE - 1));
        // First project slot
        assert!(!handle_is_sumo_core(HANDLE_PROJECT_BASE));
        assert!(handle_is_project(HANDLE_PROJECT_BASE));
        assert!(handle_is_well_known(HANDLE_PROJECT_BASE));
        // Last project slot
        assert!(handle_is_project(HANDLE_DYNAMIC_BASE - 1));
        // Dynamic range — not well-known, not project
        assert!(!handle_is_project(HANDLE_DYNAMIC_BASE));
        assert!(!handle_is_sumo_core(HANDLE_DYNAMIC_BASE));
    }

    #[test]
    fn well_known_handles_have_distinct_values() {
        let hs = [
            HANDLE_SW_AUTHORITY,
            HANDLE_DEVICE_DECRYPT,
            HANDLE_IAM_SIGNING,
            HANDLE_KEY_AUTHORITY,
            HANDLE_JWT_SIGNING,
            HANDLE_STORAGE,
            HANDLE_OPERATIONAL_ISSUER,
            HANDLE_HIGH_CONSEQUENCE_ISSUER,
        ];
        for (i, a) in hs.iter().enumerate() {
            for b in &hs[i + 1..] {
                assert_ne!(a, b, "duplicate well-known handle 0x{a:04x}");
            }
        }
    }

    #[test]
    fn magic_and_version_are_vhs_v3() {
        assert_eq!(&VHSM_MAGIC, b"VHS");
        assert_eq!(VHSM_VERSION, 0x03);
    }

    #[test]
    fn response_ok_sets_status_zero() {
        let r = Response::ok(Op::GetRandom as u32, 42, b"hi".to_vec());
        assert_eq!(r.status, StatusCode::Ok as u32);
        assert_eq!(r.status, 0);
        assert_eq!(r.session_id, 42);
        assert_eq!(r.payload, b"hi");
    }

    #[test]
    fn response_err_clears_payload() {
        let r = Response::err(Op::Sign as u32, 7, StatusCode::PermissionDeny);
        assert_eq!(r.status, StatusCode::PermissionDeny as u32);
        assert_eq!(r.status, 0x02);
        assert_eq!(r.session_id, 7);
        assert!(r.payload.is_empty());
    }

    #[test]
    fn status_code_values_match_protocol_spec() {
        // These are wire-visible constants — freeze them so accidental
        // reordering of the enum doesn't silently renumber the wire.
        assert_eq!(StatusCode::Ok as u32, 0);
        assert_eq!(StatusCode::InvalidHandle as u32, 1);
        assert_eq!(StatusCode::PermissionDeny as u32, 2);
        assert_eq!(StatusCode::PolicyReject as u32, 3);
        assert_eq!(StatusCode::HseError as u32, 4);
        assert_eq!(StatusCode::InvalidParam as u32, 5);
        assert_eq!(StatusCode::NoResource as u32, 6);
        assert_eq!(StatusCode::StorageError as u32, 7);
        assert_eq!(StatusCode::CryptoError as u32, 8);
        assert_eq!(StatusCode::Internal as u32, 9);
    }

    #[test]
    fn op_values_match_protocol_spec() {
        // Wire-visible operation codes — freeze against accidental reordering.
        assert_eq!(Op::GetRandom as u32, 0x0001);
        assert_eq!(Op::KeyGenerate as u32, 0x0010);
        assert_eq!(Op::Encrypt as u32, 0x0020);
        assert_eq!(Op::MacGenerate as u32, 0x0030);
        assert_eq!(Op::Sign as u32, 0x0040);
        assert_eq!(Op::GetHandleInfo as u32, 0x0050);
    }
}
