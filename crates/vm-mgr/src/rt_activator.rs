use machine_mgr::{BankActivator, BankActivatorError};
use std::path::Path;
use std::process::Command;

pub struct RtBankActivator {
    launcher_path: String,
}

impl RtBankActivator {
    pub fn new(launcher_path: impl Into<String>) -> Self {
        Self {
            launcher_path: launcher_path.into(),
        }
    }
}

impl BankActivator for RtBankActivator {
    fn activate(&self, bank_dir: &Path) -> Result<(), BankActivatorError> {
        let status = Command::new(&self.launcher_path)
            .args(["--bank", &bank_dir.to_string_lossy(), "--clear-first"])
            .status()
            .map_err(|e| {
                BankActivatorError::Failed(format!(
                    "failed to exec rt-launcher at {}: {e}",
                    self.launcher_path
                ))
            })?;
        if !status.success() {
            return Err(BankActivatorError::Failed(format!(
                "rt-launcher exited with {}",
                status.code().unwrap_or(-1)
            )));
        }
        Ok(())
    }
}
