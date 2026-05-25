//! VM update + diagnostics service.
//!
//! Owns the top-level `Machine` (from `machine-mgr`) and translates between
//! SOVD REST / UDS wire semantics and per-component operations. Hosts the
//! `vm-sovd` binary: SUIT envelope validation, streaming firmware pipeline,
//! per-bank NV DID resolution, and the OTA install/commit/rollback engine.
//!
//! # Layering
//!
//! ```text
//!   sovd-core::DiagnosticBackend (wire-shape layer)
//!         │
//!         │ implemented by
//!         ▼
//!   diag_backend::ComponentDiagBackend     ← migration adapter
//!         │                                  (routes via machine-mgr where wired,
//!         │                                   falls back to legacy VmBackend)
//!         ▼
//!   machine_mgr::Component
//!         │
//!         │ implemented by
//!         ▼
//!   component_adapter::VmBackendComponent
//!         │
//!         │ delegates to
//!         ▼
//!   backend::VmBackend<D: BlockDevice>    ← legacy per-bank-set type,
//!                                           one instance per component
//! ```
//!
//! # Key modules
//!
//! - [`backend`]  — `VmBackend`: OTA / session / DID impl, one per component
//! - [`ota`]      — install, commit, rollback, image hash verification
//! - [`did`]      — runtime → FW meta → factory → dynamic DID resolution
//! - [`suit_provider`] + [`manifest_provider`] — SUIT envelope validation
//! - [`streaming`] — upload pipeline (decompress + decrypt + hash streaming)

pub mod backend;
pub mod bank_seed;
pub mod bank_spec;
pub mod component_adapter;
pub mod diag_backend;
pub mod did;
pub mod manifest;
pub mod manifest_provider;
pub mod ota;
pub mod streaming;
pub mod suit_provider;

pub mod sovd {
    pub mod security;
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod sovd_tests;

#[cfg(test)]
mod component_adapter_tests;

#[cfg(test)]
mod diag_backend_tests;

#[cfg(test)]
mod wrapper_http_tests;

#[cfg(test)]
mod bank_seed_integration_tests;
