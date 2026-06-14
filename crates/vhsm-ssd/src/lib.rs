//! vHSM SSD — host-side daemon terminating the handle-based vHSM v3 wire
//! protocol spoken by the guest `/dev/vhsm` driver.
//!
//! Transport is TCP on a private host bridge (`vbr-vhsm`, 192.168.99.0/24)
//! provisioned by the orchestrator. Guest identity is established by a
//! cert-based handshake at connection time (see [`auth`]): HELLO → AUTH (or
//! ENROLL on first-boot), binding a [`auth::Principal`] to the connection.
//! Authorisation is statement-based; see [`iam`] for the YAML policy DSL.
//!
//! Requests are binary frames (see [`proto`] + [`codec`]); every op carries
//! a handle in the 0x0001..=0x00FF well-known range or 0x0100+ dynamic
//! range, and resolves through the [`handle_table`] to a keystore entry.
//!
//! Implemented ops: get_random, key_generate, key_delete, encrypt, decrypt,
//! mac_generate/verify, sign, verify, get_handle_info, get_pubkey, get_cert.
//!
//! Crypto is delegated to an `HsmCryptoProvider` (see the `hsm` crate).
//! Today that's `SimHsm` (RustCrypto + on-disk keys); production brings up
//! a board-specific provider talking to HSE/TRNG hardware.

pub mod audit;
pub mod auth;
pub mod bootstrap;
pub mod cert;
pub mod codec;
pub mod crossnode;
pub mod extension_manifest;
pub mod handle_table;
pub mod handler;
pub mod iam;
pub mod proto;
pub mod serve;
pub mod tls;
pub mod transport;
