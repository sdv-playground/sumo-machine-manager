//! vHSM SSD — host-side daemon terminating the handle-based vHSM v2 wire
//! protocol spoken by the guest `/dev/vhsm` driver.
//!
//! Transport is TCP on a private host bridge (`vbr-vhsm`, 192.168.99.0/24)
//! provisioned by the orchestrator. Guest identity comes from the source IP
//! of the connecting socket; the orchestrator pins each guest's MAC at QEMU
//! launch and dnsmasq pins MAC → IP via static lease, so a guest's IP is as
//! unspoofable as a vsock CID was — the trust anchor is the orchestrator,
//! not a pre-shared key. See [`policy`] for the IP allow-list, [`transport`]
//! for the TCP listener, and [`handle_table`] for how `vm_id` (resolved from
//! the source IP) gates dynamic-handle access.
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

pub mod proto;
pub mod codec;
pub mod handle_table;
pub mod policy;
pub mod handler;
pub mod transport;
pub mod extension_manifest;
pub mod audit;
pub mod cert;
pub mod bootstrap;
pub mod iam;
pub mod auth;
