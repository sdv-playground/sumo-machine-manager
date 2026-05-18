use std::fs;
use std::path::{Path, PathBuf};

use machine_mgr::error::{MachineError, MachineResult};
use nv_store::types::Bank;

/// Configuration for an AppComponent.
pub struct AppConfig {
    /// Component id (e.g. "supernova").
    pub id: String,
    /// Base path containing A/, B/, current symlink (e.g. /data/supernova/).
    pub base_path: PathBuf,
}

/// Which bank directory name to use.
pub enum BankDir {
    A,
    B,
}

impl From<Bank> for BankDir {
    fn from(bank: Bank) -> Self {
        match bank {
            Bank::A => BankDir::A,
            Bank::B => BankDir::B,
        }
    }
}

impl BankDir {
    pub fn name(&self) -> &'static str {
        match self {
            BankDir::A => "A",
            BankDir::B => "B",
        }
    }
}

/// Atomically flip the `current` symlink to point to the given bank directory.
pub fn flip_current_symlink(base_path: &Path, bank: Bank) -> MachineResult<()> {
    let target = BankDir::from(bank).name();
    let link_path = base_path.join("current");
    let tmp_path = base_path.join(".current.tmp");

    // Remove stale temp link if it exists
    let _ = fs::remove_file(&tmp_path);

    // Create new symlink at temp path, then atomically rename
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, &tmp_path).map_err(|e| {
            MachineError::Storage(format!("symlink create failed: {e}"))
        })?;
    }
    #[cfg(not(unix))]
    {
        return Err(MachineError::Internal("symlink flip requires unix".into()));
    }

    fs::rename(&tmp_path, &link_path).map_err(|e| {
        MachineError::Storage(format!("symlink rename failed: {e}"))
    })?;

    Ok(())
}

/// Ensure the base_path directory structure exists (A/, B/, current→A).
///
/// Called by integration tests and by manual bootstrap on a fresh
/// machine; not yet wired into supernova's normal startup path,
/// which currently relies on the bank dirs existing from device
/// imaging. Kept as part of the public surface so the bootstrap
/// route stays accessible.
#[allow(dead_code)]
pub fn ensure_layout(base_path: &Path) -> MachineResult<()> {
    fs::create_dir_all(base_path.join("A"))
        .map_err(|e| MachineError::Storage(format!("mkdir A: {e}")))?;
    fs::create_dir_all(base_path.join("B"))
        .map_err(|e| MachineError::Storage(format!("mkdir B: {e}")))?;

    let link_path = base_path.join("current");
    if !link_path.exists() {
        flip_current_symlink(base_path, Bank::A)?;
    }

    // Ensure start.sh symlink at top level
    let start_link = base_path.join("start.sh");
    if !start_link.exists() {
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink("current/start.sh", &start_link);
        }
    }

    Ok(())
}
