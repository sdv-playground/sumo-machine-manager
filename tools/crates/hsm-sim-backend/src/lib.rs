//! Software HSM backend.
//!
//! [`SimHsm`] is a file-keystore + RustCrypto implementation of the `hsm`
//! crate's [`HsmProvider`](hsm::HsmProvider) / [`HsmCryptoProvider`](hsm::HsmCryptoProvider)
//! contract, paired with the `hsm-sim-service` bin that serves it over link-B.
//!
//! This is the software-HSM link-B backend for **sim / dev deployments** — on
//! sim devices (e.g. the QEMU-emulated CVC) the host machine manager spawns and
//! owns it as the node's HSM, and it stays the dev-mode backend until real-HSM
//! integration lands. It is **just another link-B implementation**, not
//! privileged: hardware production runs a vendor C HSE service implementing the
//! same `hsm-link-b` contract, and `vhsm-ssd` selects between them purely by
//! which backend command runs — it can't tell them apart. Verify any backend
//! (this one included) with the `hsm-conformance` suite.
//!
//! **Caution:** being pure software over an on-disk keystore, it provides **no
//! hardware key protection** — key material is only as safe as the keystore
//! files. Do not treat a SimHsm-backed node as holding hardware-grade secrets.
//!
//! The keystore wire schema (`hsm::payload`), the traits/types, `KeyRole`, the
//! `ivd` signing logic, and the `link_b` bridge all live in the core `hsm`
//! contract crate; this crate is only the software *implementation* of that
//! contract.

#[cfg(feature = "crypto")]
pub mod crypto;
pub mod sim;

pub use sim::SimHsm;
