//! Guest-side v3 CWT handshake (HELLO/AUTH/ENROLL) + cert persistence.
//!
//! Used by the guest vhsm-daemons (`vhsm-daemon-{linux,qnx}`) for their ONE
//! persistent upstream connection to `vhsm-ssd`: they run HELLO → AUTH (or
//! HELLO → ENROLL on first boot) once at connect, then forward per-app requests
//! verbatim. Per-app callers (the plain [`crate::VhsmClient`] over UDS/devctl)
//! talk to the local daemon and never run this layer.
//!
//! Gated behind the `guest-auth` feature so host crypto callers (cross-node
//! mTLS, the `vhsm-provider`) don't pull in p256/sha2/rand. Reuses the shared
//! [`vhsm_proto`] framing + op codes + `AuthFailReason`.
//!
//! See `guest-vm-spec/specs/vhsm/protocol.md` §11 for the wire-level definition.

pub mod handshake;
pub mod persist;

pub use handshake::{authenticate, cert_thumbprint, enroll, enroll_assisted, AuthError, Principal};
pub use persist::{AuthConfig, BOOTSTRAP_TOKEN_LEN, IDENTITY_KEY_LEN};

/// Length of the server-issued HELLO nonce.
pub const NONCE_LEN: usize = 16;

/// Domain-separation tag prefixed to the proof-of-possession signature input.
/// Prevents reuse of the client's identity-key signature in any other protocol;
/// must match `vhsm-ssd::auth::PROOF_DOMAIN_TAG` exactly.
pub const PROOF_DOMAIN_TAG: &[u8] = b"vhsm-auth-v1";
