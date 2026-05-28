//! IFS (Initial Filesystem) activation backends.
//!
//! QNX IPL loads the IFS from a fixed path on the boot partition.
//! Unlike rootfs images, IFS cannot use symlink-based A/B switching
//! because IPL does not follow symlinks.
//!
//! Each backend implements `BankActivator` (from `machine_mgr`) — the
//! trait that copies a new IFS bank image to the active boot location.

pub mod dev;
pub mod partition;

// Re-export the trait and error from machine-mgr for convenience.
pub use machine_mgr::{BankActivator, BankActivatorError};
