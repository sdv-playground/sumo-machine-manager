//! VM runner trait — platform abstraction for starting/stopping VMs.
//!
//! Implementations:
//!
//! - `QemuRunner`: builds QEMU command line, manages ivshmem-server + simulators
//! - `DummyRunner`: instant no-ops for components without a real VM
//! - `QnxRunner`: stub for QNX qvm integration (future)

pub mod dummy;
#[cfg(target_os = "linux")]
pub mod qemu;
pub mod qnx;

use crate::config::VmDefinition;
use std::time::Duration;

#[derive(Debug)]
pub enum RunnerError {
    Io(std::io::Error),
    Config(String),
    ProcessFailed(String),
}

impl From<std::io::Error> for RunnerError {
    fn from(e: std::io::Error) -> Self {
        RunnerError::Io(e)
    }
}

impl std::fmt::Display for RunnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunnerError::Io(e) => write!(f, "I/O error: {e}"),
            RunnerError::Config(s) => write!(f, "config error: {s}"),
            RunnerError::ProcessFailed(s) => write!(f, "process failed: {s}"),
        }
    }
}

impl std::error::Error for RunnerError {}

/// Handle to a running VM.
pub struct VmHandle {
    #[allow(dead_code)]
    pub name: String,
    pub pid: Option<u32>,
}

pub trait VmRunner: Send {
    /// Release resources from a previous lifetime of this VM (orphan
    /// qvm processes, lingering devb-loopback daemons holding the
    /// bank's rootfs.img open). Must be called by VmManager BEFORE
    /// any pre-launch read of the bank — otherwise verify hits EBUSY
    /// on the rootfs.img file. Idempotent: a no-op when nothing is
    /// holding anything.
    ///
    /// Default: no-op. QnxRunner overrides to slay leftover qvm +
    /// devb-loopback for this VM.
    fn prepare_for_launch(&mut self, _name: &str, _def: &VmDefinition) {}

    /// Start a VM with the given definition.
    fn start(&mut self, name: &str, def: &VmDefinition) -> Result<VmHandle, RunnerError>;

    /// Stop a running VM (force kill).
    fn stop(&mut self, handle: &VmHandle) -> Result<(), RunnerError>;

    /// Check if a VM is still running.
    fn is_running(&self, handle: &VmHandle) -> bool;

    /// Block until the VM exits. Returns the exit code, or None if unknown.
    #[allow(dead_code)]
    fn wait(&mut self, handle: &VmHandle) -> Result<Option<i32>, RunnerError>;

    /// Clean up all host-side resources (ivshmem servers, simulators, sockets).
    fn cleanup(&mut self);

    /// Wait until the VM signals it is ready (e.g., health device heartbeat).
    /// Default: returns immediately (always ready).
    #[allow(dead_code)]
    fn wait_ready(&mut self, _handle: &VmHandle, _timeout: Duration) -> Result<(), RunnerError> {
        Ok(())
    }

    /// Attempt graceful shutdown, then force-kill if still running after timeout.
    /// Default: calls stop() immediately.
    #[allow(dead_code)]
    fn graceful_shutdown(
        &mut self,
        handle: &VmHandle,
        _timeout: Duration,
    ) -> Result<(), RunnerError> {
        self.stop(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runner_error_display_covers_all_variants() {
        let ioe = RunnerError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "x"));
        let cfg = RunnerError::Config("bad config".into());
        let proc = RunnerError::ProcessFailed("spawn failed".into());
        assert!(ioe.to_string().contains("I/O"));
        assert!(cfg.to_string().contains("config"));
        assert!(proc.to_string().contains("process"));
    }

    #[test]
    fn runner_error_from_io_error() {
        let e: RunnerError =
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "nope").into();
        assert!(matches!(e, RunnerError::Io(_)));
    }

    #[test]
    fn runner_error_is_std_error() {
        fn take<E: std::error::Error>(_: E) {}
        take(RunnerError::Config("x".into()));
    }
}
