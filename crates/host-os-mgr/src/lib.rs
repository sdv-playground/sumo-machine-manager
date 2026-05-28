//! Host OS manager — manages the host operating system image lifecycle.
//!
//! Responsibilities:
//! - A/B boot partition writes (stage new IFS + root image)
//! - Boot policy (trial boot → commit or auto-rollback)
//! - IFS activation (copy staged image to boot location)
//! - Reboot coordination (signal readiness, trigger reboot)
//!
//! This is NOT a VM. The host OS boots bare-metal (or as the hypervisor
//! host) and cannot be hot-updated — it requires a full reboot cycle.
//! The update model is therefore simpler than guest VMs:
//!
//! 1. Flash: write new image to inactive bank
//! 2. Activate: copy IFS to boot location
//! 3. Reboot: IPL loads the new IFS
//! 4. Trial: boot manager counts boots, auto-rolls back if unhealthy
//! 5. Commit: mark new bank as committed (raises anti-rollback floor)

pub mod ifs;
pub mod component;

pub use component::HostOsComponent;
pub use ifs::{BankActivator, BankActivatorError};
