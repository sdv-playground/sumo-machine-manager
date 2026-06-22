//! VM update + diagnostics service.
//!
//! Owns the top-level `Machine` (from `machine-mgr`) and translates between
//! SOVD REST / UDS wire semantics and per-component operations. Hosts the
//! `vm-sovd` binary: SUIT envelope validation, streaming firmware pipeline,
//! per-bank NV DID resolution, and the OTA install/commit/rollback engine.
//!
//! # Layering
//!
//! `ComponentBackend` IS the per-component `DiagnosticBackend` and is wired
//! straight into SOVD for every component:
//!
//! ```text
//!   sovd-core::DiagnosticBackend (wire-shape layer)
//!         │
//!         │ implemented by
//!         ▼
//!   backend::ComponentBackend<D: BlockDevice>    ← the complete engine:
//!                                           data + DIDs + identity overlay +
//!                                           faults + OTA lifecycle + modes,
//!                                           one instance per component
//! ```
//!
//! vm2 is the one exception. A SUIT envelope on its `/updates` wire may target
//! the VM bank set OR the in-VM container image, and that routing decision
//! lives in `app_install_router::AppInstallRouterComponent`. There,
//! `install_router_diag::InstallRouterDiag` wraps the engine: it intercepts
//! ONLY the install/flash methods (routing them through the router) and
//! delegates everything else (data, faults, modes, …) to the engine.
//!
//! ```text
//!   sovd-core::DiagnosticBackend
//!         │ implemented by
//!         ▼
//!   install_router_diag::InstallRouterDiag   ← vm2 only
//!     ├─ install/flash ─▶ machine_mgr::Component (AppInstallRouterComponent)
//!     └─ everything else ─▶ backend::ComponentBackend (the engine)
//! ```
//!
//! `component_adapter::ComponentAdapter` still exposes `ComponentBackend` as a
//! `machine_mgr::Component` for the `MachineRegistry` (orthogonal to SOVD).
//!
//! # Key modules
//!
//! - [`backend`]  — `ComponentBackend`: OTA / session / DID impl, one per component
//! - [`ota`]      — install, commit, rollback, image hash verification
//! - [`did`]      — runtime → FW meta → factory → dynamic DID resolution
//! - [`suit_provider`] + [`manifest_provider`] — SUIT envelope validation
//! - [`streaming`] — upload pipeline (decompress + decrypt + hash streaming)

pub mod app_install_router;
pub mod backend;
pub mod bank_provider;
pub mod bank_seed;
pub mod bank_spec;
pub mod component_adapter;
pub mod did;
pub mod dispatcher;
pub mod install_router_diag;
pub mod manifest;
pub mod manifest_provider;
pub mod ota;
pub mod streaming;
pub mod suit_provider;

pub mod sovd {
    pub mod authz;
    pub mod delegated_rights;
    pub mod delegation;
    pub mod freshness;
    pub mod gateway;
    pub mod identity;
    pub mod issuer_keys;
    pub mod routes;
    pub mod security;
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod sovd_tests;

#[cfg(test)]
mod component_adapter_tests;

#[cfg(test)]
mod install_router_diag_tests;

#[cfg(test)]
mod wrapper_http_tests;

#[cfg(test)]
mod bank_seed_integration_tests;
