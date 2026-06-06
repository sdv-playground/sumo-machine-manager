//! machine-mgr — semantic API behind the SOVD diagnostic server.
//!
//! The SOVD-facing layer in `vm-mgr` holds an `Arc<dyn Machine>`.
//! Each `Machine` exposes a registry of [`Component`] objects — one per
//! independently-updatable thing (hypervisor, vm1, vm2, hsm, ...). Components
//! declare their [`Capabilities`] so an external orchestrator (in-vehicle
//! OTA or workshop tool) can plan against them.
//!
//! Every [`Component`] method has a `NotSupported` default; a concrete
//! component only overrides the operations it actually supports, and the
//! [`Capabilities`] it returns must match what it actually implements.
//!
//! Production vs. simulation deployments differ only in how the `Machine`
//! is composed in `vm-sovd`'s `main()`. The trait surface and the SOVD
//! adapter layer are identical across deployments.
//!
//! # Hierarchy
//!
//! ```text
//!                          Machine  (top-level registry)
//!                             │
//!             ┌───────────────┼───────────────┬──────────────┐
//!             │               │               │              │
//!        hypervisor         vm1             vm2            hsm
//!        (Component)     (Component)    (Component)    (Component)
//!             │               │               │              │
//!             └───────────────┴───────────────┴──────────────┘
//!                 each a ComponentAdapter<D: BlockDevice>
//!                 (see vm-mgr::component_adapter)
//! ```
//!
//! Every Component today is a thin `ComponentAdapter<D>` wrapper around
//! a `vm_mgr::ComponentBackend<D>` bound to a specific `BankSet`. This is
//! a migration layer: as more Component methods get wired end-to-end, the
//! legacy `ComponentBackend` surface shrinks; once it's vestigial the adapter will
//! implement `Component` directly.
//!
//! # Component State Matrix
//!
//! What each concrete component does and how ready it is right now:
//!
//! | Component  | Bank model | Install | Commit / Rollback | Session / Security | DIDs | Notes                                     |
//! |------------|------------|---------|-------------------|--------------------|------|-------------------------------------------|
//! | hypervisor | A/B        | ✓       | ✓                 | ✓                  | ✓    | host-OS update; IFS activation on reboot  |
//! | vm1        | A/B        | ✓       | ✓                 | ✓                  | ✓    | Debian Linux guest                        |
//! | vm2        | A/B        | ✓       | ✓                 | ✓                  | ✓    | QNX 7.1 guest                             |
//! | hsm        | single     | ✓       | —  (no rollback)  | ✓                  | ✓    | SUIT envelope → keystore; no trial boot   |
//!
//! All four run through the same `ComponentBackend` codepath — per-component state
//! lives in the NV store (see the `nv-store` crate) keyed by `BankSet`.
//!
//! # Platform Maturity
//!
//! The same business logic is intended to run on three targets. Current
//! standing (surveyed 2026-04):
//!
//! - **Linux dev (QEMU + file-backed NV)** — full pipeline works end-to-end:
//!   factory provisioning, OTA install, commit, rollback, health monitoring.
//! - **QNX-emulated (QNX host, simulated peripherals)** — ~70% ready. The
//!   `QnxRunner` exists; missing pieces are `SharedMemory`/`Doorbell` impls
//!   for QNX `shm_open` + IPC, a raw-partition or file-backed `BlockDevice`,
//!   and a `NullCanBackend` stub so `vm-devices` compiles on QNX.
//! - **QNX with real hardware** — abstractions in place but concrete impls
//!   missing: `QnxHsm` is a stub, `HseEncryptor` for `SecstoreEncryptor`
//!   isn't written yet, real CAN adapter pending.

pub mod bank_activator;
pub mod bank_provider;
pub mod component;
pub mod error;
pub mod machine;
pub mod types;

#[cfg(test)]
mod tests;

pub use bank_activator::{BankActivator, BankActivatorError};
pub use bank_provider::{
    BankError, BankProvider, FirmwareIdentity, InstalledFile, InstalledFirmware,
};
pub use component::Component;
pub use error::{MachineError, MachineResult};
pub use machine::{Machine, MachineRegistry};
pub use types::*;

// Re-exports of SOVD wire types that are also our domain types.
// The diagserver layer treats SOVD as the canonical interface, so where
// a wire type already names the right thing we use it directly.
pub use sovd_core::{
    ActivationState, ClearFaultsResult, DataValue, EntityInfo, Fault, FaultFilter, FaultsResult,
    FlashProgress, FlashState, FlashStatus, PackageInfo, ParameterInfo, VerifyResult,
};
