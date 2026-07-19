//! Administrative deactivation trait — abstracts the platform-specific step
//! of taking a component's *runtime* down when it is administratively
//! disabled (e.g. stop a VM via vm-service, erase the RT/M7 slot via
//! m7loader).
//!
//! Lives in `machine-mgr` so that `component-mgr` (the generic vm-service-stop
//! deactivator) and host machine managers (the RT erase deactivator) can
//! implement the same trait without circular dependencies — the same split as
//! [`crate::bank_activator::BankActivator`].
//!
//! Contract for implementations:
//!
//! - **Enact only.** Stop/erase the component's runtime. Implementations
//!   never touch NV — the caller (`component-mgr`'s admin-state op) owns the
//!   persisted admin flag, and persists it BEFORE enacting so a crash between
//!   the two converges at the next boot (the start gate skips a disabled
//!   component).
//! - **Never reboot the node.** When completing the deactivation needs a node
//!   reset (RT erase: the M7 keeps running from SRAM until the next boot),
//!   return [`DeactivateOutcome::reboot_required`] `= true` — the op arms it
//!   and the tester issues the reset (the house "activate ≠ reboot" rule).

/// Errors returned by [`Deactivator::deactivate`].
#[derive(Debug)]
pub enum DeactivateError {
    /// An I/O error occurred during deactivation.
    Io(std::io::Error),
    /// Deactivation failed for a domain-specific reason.
    Failed(String),
}

impl std::fmt::Display for DeactivateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeactivateError::Io(e) => write!(f, "deactivation I/O error: {e}"),
            DeactivateError::Failed(msg) => write!(f, "deactivation failed: {msg}"),
        }
    }
}

impl std::error::Error for DeactivateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DeactivateError::Io(e) => Some(e),
            DeactivateError::Failed(_) => None,
        }
    }
}

impl From<std::io::Error> for DeactivateError {
    fn from(e: std::io::Error) -> Self {
        DeactivateError::Io(e)
    }
}

/// Outcome of a successful [`Deactivator::deactivate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeactivateOutcome {
    /// True when the deactivation only completes at the next node reset (RT
    /// erase — the M7 keeps running from SRAM until then). The op reports it
    /// to the caller, who issues the existing `status/restart`; the
    /// deactivator itself never reboots. False for VMs (the stop is
    /// immediate).
    pub reboot_required: bool,
}

/// Trait for enacting a component's administrative disable.
///
/// Implementors perform whatever platform-specific step takes the
/// component's runtime down. Examples:
///
/// - **VM**: POST `/vms/{name}/stop` to vm-service (the generic
///   vm-service-stop deactivator built by component-factory)
/// - **RT/M7**: `m7loader` erase of the RT slot (host machine manager)
///
/// A component is administratively *disableable* iff its factory equips it
/// with a `Deactivator` — disableability is structural, not a name list.
pub trait Deactivator: Send + Sync {
    fn deactivate(&self) -> Result<DeactivateOutcome, DeactivateError>;
}
