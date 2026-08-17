//! `machine_mgr::Component` implementation for the host OS.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use machine_mgr::component::Component;
use machine_mgr::error::{MachineError, MachineResult};
use machine_mgr::types::{Capabilities, FlashCaps, LifecycleCaps, RuntimeState, RuntimeStatus};
use nv_store::block::BlockDevice;
use nv_store::store::NvStore;
use nv_store::types::{Bank, BankSet};

use machine_mgr::BankActivator;

pub struct HostOsComponent<D: BlockDevice> {
    nv: Arc<Mutex<NvStore<D>>>,
    // Kept as an owned Arc so the activator outlives any in-flight
    // host-os work that component-mgr's backend drives via its own copy.
    // HostOsComponent itself doesn't call into it (yet).
    _bank_activator: Arc<dyn BankActivator>,
    capabilities: Capabilities,
}

impl<D: BlockDevice + Send + 'static> HostOsComponent<D> {
    pub fn new(nv: Arc<Mutex<NvStore<D>>>, bank_activator: Arc<dyn BankActivator>) -> Self {
        let reset_kind = bank_activator.reset_kind();
        Self {
            nv,
            _bank_activator: bank_activator,
            capabilities: Capabilities {
                did_store: true,
                flash: Some(FlashCaps {
                    dual_bank: true,
                    supports_rollback: true,
                    supports_trial_boot: true,
                    abortable_after_finalize: true,
                    // Inherits from the underlying activator — both Dev and
                    // Partition impls return RequiresEcuReset since the new
                    // IFS doesn't run until the host reboots.
                    reset_kind,
                }),
                lifecycle: Some(LifecycleCaps {
                    restartable: true,
                    has_runtime_state: true,
                }),
                hsm: None,
                dtcs: false,
                clear_dtcs: false,
            },
        }
    }

    fn active_bank(&self) -> Option<Bank> {
        let nv = self.nv.lock().unwrap();
        nv.read_boot_state()
            .map(|s| s.banks[BankSet::Os.as_index()].active_bank)
    }

    fn is_trial(&self) -> bool {
        let nv = self.nv.lock().unwrap();
        nv.read_boot_state()
            .map(|s| !s.banks[BankSet::Os.as_index()].committed)
            .unwrap_or(false)
    }
}

#[async_trait]
impl<D: BlockDevice + Send + 'static> Component for HostOsComponent<D> {
    fn id(&self) -> &str {
        "host"
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    async fn restart(&self) -> MachineResult<()> {
        tracing::warn!("host-os restart requested — triggering reboot");
        std::process::Command::new("shutdown")
            .args(["-r", "now"])
            .status()
            .map_err(|e| MachineError::Internal(format!("reboot failed: {e}")))?;
        Ok(())
    }

    async fn runtime_state(&self) -> MachineResult<RuntimeState> {
        let trial = self.is_trial();
        let bank = self.active_bank();
        let detail = serde_json::json!({
            "bank": bank.map(|b| format!("{b:?}")),
            "trial": trial,
        });
        Ok(RuntimeState {
            status: RuntimeStatus::Running,
            detail,
        })
    }

    async fn commit_install(&self, _id: &machine_mgr::types::FlashId) -> MachineResult<()> {
        let mut nv = self.nv.lock().unwrap();
        let mut state = nv
            .read_boot_state()
            .ok_or_else(|| MachineError::Internal("no boot state".into()))?;

        let idx = BankSet::Os.as_index();
        if state.banks[idx].committed {
            return Err(MachineError::InvalidArgument("already committed".into()));
        }

        state.banks[idx].committed = true;
        state.banks[idx].boot_count = 0;
        nv.write_boot_state(&mut state)
            .map_err(|e| MachineError::Storage(format!("{e}")))?;

        tracing::info!("host-os: boot committed");
        Ok(())
    }

    async fn rollback_install(&self, _id: &machine_mgr::types::FlashId) -> MachineResult<()> {
        let mut nv = self.nv.lock().unwrap();
        let mut state = nv
            .read_boot_state()
            .ok_or_else(|| MachineError::Internal("no boot state".into()))?;

        let idx = BankSet::Os.as_index();
        if state.banks[idx].committed {
            return Err(MachineError::PolicyRejected(
                "cannot rollback committed boot".into(),
            ));
        }

        let old = state.banks[idx].active_bank;
        state.banks[idx].active_bank = old.other();
        state.banks[idx].committed = true;
        state.banks[idx].boot_count = 0;
        nv.write_boot_state(&mut state)
            .map_err(|e| MachineError::Storage(format!("{e}")))?;

        tracing::info!("host-os: rolled back from {old:?} to {:?}", old.other());
        Ok(())
    }
}
