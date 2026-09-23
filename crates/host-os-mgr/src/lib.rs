//! Host OS manager — the [`BankActivator`] impls for the host operating
//! system image: copy a staged IFS to the boot location ([`ifs::dev`],
//! mount + atomic copy) or write it to a raw boot partition
//! ([`ifs::partition`]).
//!
//! The lifecycle around them — boot policy, trial counting, commit /
//! rollback, reboot coordination — is driven by the generic component
//! state machine (`component-mgr`) over these activators; this crate is
//! only the host-specific write.
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

pub use ifs::{BankActivator, BankActivatorError};
