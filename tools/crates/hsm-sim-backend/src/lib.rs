//! Non-production software HSM backend.
//!
//! [`SimHsm`] is a file-keystore + RustCrypto implementation of the `hsm`
//! crate's [`HsmProvider`](hsm::HsmProvider) / [`HsmCryptoProvider`](hsm::HsmCryptoProvider)
//! contract, paired with the `hsm-sim-service` bin that serves it over link-B.
//!
//! **NON-PRODUCTION.** This is a *software reference* backend for dev / test /
//! CI — **just another link-B implementation**, not privileged. A real
//! deployment runs a vendor C HSE service implementing the same `hsm-link-b`
//! contract; `vhsm-ssd` selects between them purely by `--backend-cmd` and can't
//! tell them apart. Verify any backend (this one included) with the
//! `hsm-conformance` suite.
//!
//! The keystore wire schema (`hsm::payload`), the traits/types, `KeyRole`, the
//! `ivd` signing logic, and the `link_b` bridge all live in the core `hsm`
//! contract crate; this crate is only the sim *implementation* of that contract.

#[cfg(feature = "crypto")]
pub mod crypto;
pub mod sim;

pub use sim::SimHsm;
