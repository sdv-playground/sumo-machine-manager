//! Bank activation trait — abstracts the platform-specific step of making
//! a staged bank directory "active" (e.g. IFS copy to boot partition,
//! RT-launcher reload, container image import).
//!
//! Lives in `machine-mgr` so that both `host-os-mgr` (the original IFS
//! activator) and `vm-mgr` (RT launcher, future backends) can implement
//! the same trait without circular dependencies.

use std::path::Path;

/// Errors returned by [`BankActivator::activate`].
#[derive(Debug)]
pub enum BankActivatorError {
    /// An I/O error occurred during activation.
    Io(std::io::Error),
    /// Activation failed for a domain-specific reason.
    Failed(String),
}

impl std::fmt::Display for BankActivatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BankActivatorError::Io(e) => write!(f, "bank activation I/O error: {e}"),
            BankActivatorError::Failed(msg) => write!(f, "bank activation failed: {msg}"),
        }
    }
}

impl std::error::Error for BankActivatorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BankActivatorError::Io(e) => Some(e),
            BankActivatorError::Failed(_) => None,
        }
    }
}

impl From<std::io::Error> for BankActivatorError {
    fn from(e: std::io::Error) -> Self {
        BankActivatorError::Io(e)
    }
}

/// Trait for activating a staged bank directory.
///
/// Implementors perform whatever platform-specific step is needed to
/// make the contents of `bank_dir` the "active" image for their
/// component. Examples:
///
/// - **IFS (host-os)**: copy/write the boot image to the boot partition
/// - **RT launcher**: exec rt-launcher with `--bank <dir> --clear-first`
/// - **Container import**: load an OCI tarball into the container runtime
pub trait BankActivator: Send + Sync {
    fn activate(&self, bank_dir: &Path) -> Result<(), BankActivatorError>;
}
