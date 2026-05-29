//! Raw partition IFS activator for production hardware.
//!
//! Writes the IFS directly to a raw block device partition.
//! Used on real ECUs where the boot partition isn't a filesystem
//! but a raw image slot.

use std::path::Path;

use machine_mgr::{BankActivator, BankActivatorError, ResetKind};

pub struct PartitionBankActivator {
    boot_partition: String,
}

impl PartitionBankActivator {
    pub fn new(boot_partition: String) -> Self {
        Self { boot_partition }
    }
}

impl BankActivator for PartitionBankActivator {
    fn activate(&self, ifs_source: &Path) -> Result<(), BankActivatorError> {
        let image_data = std::fs::read(ifs_source)?;

        tracing::info!(
            "writing IFS ({} bytes) to raw partition {}",
            image_data.len(),
            self.boot_partition
        );

        std::fs::write(&self.boot_partition, &image_data)?;

        let _ = std::process::Command::new("sync").status();

        tracing::info!("IFS written to partition — reboot required");
        Ok(())
    }

    fn reset_kind(&self) -> ResetKind {
        // Raw partition write — new IFS runs only after the host reboots.
        ResetKind::RequiresEcuReset
    }
}
