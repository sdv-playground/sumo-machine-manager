mod boot;
pub mod docker_image;
mod install;
mod state;

pub use docker_image::{ContainerImageComponent, ContainerImageConfig, ContainerRuntimeKind};
pub use state::AppConfig;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use machine_mgr::component::Component;
use machine_mgr::error::{MachineError, MachineResult};
use machine_mgr::types::{
    Capabilities, FlashCaps, FlashId, FlashSession, LifecycleCaps, RuntimeState, RuntimeStatus,
};
use machine_mgr::{ActivationState, FlashState};
use nv_store::block::BlockDevice;
use nv_store::store::NvStore;
use nv_store::types::{Bank, BankSet};

use crate::install::InstallSession;

pub struct AppComponent<D: BlockDevice> {
    config: AppConfig,
    nv: Arc<Mutex<NvStore<D>>>,
    running_bank: Mutex<Bank>,
    capabilities: Capabilities,
    session: Mutex<Option<InstallSession>>,
}

impl<D: BlockDevice + Send + 'static> AppComponent<D> {
    pub fn new(config: AppConfig, nv: Arc<Mutex<NvStore<D>>>) -> Self {
        let running_bank = {
            let nv_guard = nv.lock().unwrap();
            nv_guard
                .read_boot_state()
                .map(|s| s.banks[BankSet::App.as_index()].active_bank)
                .unwrap_or(Bank::A)
        };

        Self {
            config,
            nv,
            running_bank: Mutex::new(running_bank),
            capabilities: Capabilities {
                did_store: true,
                flash: Some(FlashCaps {
                    dual_bank: true,
                    supports_rollback: true,
                    supports_trial_boot: true,
                    abortable_after_finalize: true,
                }),
                lifecycle: Some(LifecycleCaps {
                    restartable: true,
                    has_runtime_state: true,
                }),
                hsm: None,
                dtcs: false,
                clear_dtcs: false,
            },
            session: Mutex::new(None),
        }
    }

    /// Run boot-time trial check. Call before serving SOVD.
    /// Returns the bank that should be active after any auto-rollback.
    pub fn boot_check(&self) -> Bank {
        boot::process_app_boot(&self.config, &self.nv)
    }

    fn active_bank(&self) -> Bank {
        *self.running_bank.lock().unwrap()
    }

    fn is_trial(&self) -> bool {
        let nv = self.nv.lock().unwrap();
        nv.read_boot_state()
            .map(|s| !s.banks[BankSet::App.as_index()].committed)
            .unwrap_or(false)
    }

    fn inactive_bank(&self) -> Bank {
        self.active_bank().other()
    }

    fn bank_dir(&self, bank: Bank) -> PathBuf {
        self.config.base_path.join(match bank {
            Bank::A => "A",
            Bank::B => "B",
        })
    }
}

#[async_trait]
impl<D: BlockDevice + Send + 'static> Component for AppComponent<D> {
    fn id(&self) -> &str {
        &self.config.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    async fn start_install(&self) -> MachineResult<FlashSession> {
        if self.is_trial() {
            return Err(MachineError::PolicyRejected(
                "cannot install while in trial mode — commit or rollback first".into(),
            ));
        }

        let mut session_guard = self.session.lock().unwrap();
        if session_guard.is_some() {
            return Err(MachineError::InvalidArgument(
                "install session already active".into(),
            ));
        }

        let target = self.inactive_bank();
        let session = InstallSession::new(target, self.bank_dir(target));
        let flash_id = FlashId::new(format!("app-{target:?}"));

        *session_guard = Some(session);

        Ok(FlashSession {
            id: flash_id,
            target_bank: Some(format!("{target:?}")),
            max_chunk_size: 16 * 1024 * 1024,
        })
    }

    async fn upload_envelope(
        &self,
        _id: &FlashId,
        stream: machine_mgr::types::EnvelopeStream,
    ) -> MachineResult<String> {
        // Take the session out to avoid holding the MutexGuard across await
        let mut session = {
            let mut guard = self.session.lock().unwrap();
            guard
                .take()
                .ok_or_else(|| MachineError::UnknownFlashSession("no active session".into()))?
        };

        let result = session.upload(stream).await;

        // Put it back
        let mut guard = self.session.lock().unwrap();
        *guard = Some(session);

        result
    }

    async fn finalize_install(&self, _id: &FlashId) -> MachineResult<()> {
        let session = {
            let mut guard = self.session.lock().unwrap();
            guard
                .take()
                .ok_or_else(|| MachineError::UnknownFlashSession("no active session".into()))?
        };

        let target_bank = session.target_bank();
        session.validate_payload()?;

        // Flip the `current` symlink
        state::flip_current_symlink(&self.config.base_path, target_bank)?;

        // Update NV: active_bank = target, committed = false, boot_count = 0
        let mut nv = self.nv.lock().unwrap();
        let mut boot_state = nv
            .read_boot_state()
            .ok_or_else(|| MachineError::Internal("no boot state".into()))?;

        let idx = BankSet::App.as_index();
        boot_state.banks[idx].active_bank = target_bank;
        boot_state.banks[idx].committed = false;
        boot_state.banks[idx].boot_count = 0;
        nv.write_boot_state(&mut boot_state)
            .map_err(|e| MachineError::Storage(format!("{e}")))?;

        tracing::info!(bank = ?target_bank, "app: finalized install, reboot required");
        Ok(())
    }

    async fn commit_install(&self, _id: &FlashId) -> MachineResult<()> {
        let mut nv = self.nv.lock().unwrap();
        let mut state = nv
            .read_boot_state()
            .ok_or_else(|| MachineError::Internal("no boot state".into()))?;

        let idx = BankSet::App.as_index();
        if state.banks[idx].committed {
            return Err(MachineError::InvalidArgument("already committed".into()));
        }

        state.banks[idx].committed = true;
        state.banks[idx].boot_count = 0;
        nv.write_boot_state(&mut state)
            .map_err(|e| MachineError::Storage(format!("{e}")))?;

        // Raise security version floor
        let active = state.banks[idx].active_bank;
        if let Some(mut meta) = nv.read_fw_meta(BankSet::App, active) {
            if meta.fw_secver > meta.min_security_ver {
                meta.min_security_ver = meta.fw_secver;
                let _ = nv.write_fw_meta(BankSet::App, active, &mut meta);
            }
        }

        tracing::info!("app: boot committed");
        Ok(())
    }

    async fn rollback_install(&self, _id: &FlashId) -> MachineResult<()> {
        let mut nv = self.nv.lock().unwrap();
        let mut boot_state = nv
            .read_boot_state()
            .ok_or_else(|| MachineError::Internal("no boot state".into()))?;

        let idx = BankSet::App.as_index();
        if boot_state.banks[idx].committed {
            return Err(MachineError::PolicyRejected(
                "cannot rollback committed boot".into(),
            ));
        }

        let old = boot_state.banks[idx].active_bank;
        boot_state.banks[idx].active_bank = old.other();
        boot_state.banks[idx].committed = true;
        boot_state.banks[idx].boot_count = 0;
        nv.write_boot_state(&mut boot_state)
            .map_err(|e| MachineError::Storage(format!("{e}")))?;

        // Flip symlink back
        drop(nv);
        state::flip_current_symlink(&self.config.base_path, old.other())?;

        tracing::info!(from = ?old, to = ?old.other(), "app: rolled back");
        Ok(())
    }

    async fn abort_install(&self, _id: &FlashId) -> MachineResult<()> {
        let mut guard = self.session.lock().unwrap();
        if guard.take().is_some() {
            tracing::info!("app: install session aborted");
            Ok(())
        } else {
            Err(MachineError::UnknownFlashSession(
                "no active session".into(),
            ))
        }
    }

    async fn activation_state(&self) -> MachineResult<Option<ActivationState>> {
        let nv = self.nv.lock().unwrap();
        let boot_state = nv.read_boot_state();
        let active_bank = self.active_bank();
        let active_meta = nv.read_fw_meta(BankSet::App, active_bank);
        let previous_meta = nv.read_fw_meta(BankSet::App, active_bank.other());

        let committed = boot_state
            .as_ref()
            .map(|s| s.banks[BankSet::App.as_index()].committed)
            .unwrap_or(true);

        let version = active_meta
            .as_ref()
            .map(|m| {
                String::from_utf8_lossy(&m.fw_version)
                    .trim_end_matches('\0')
                    .to_string()
            })
            .unwrap_or_default();

        // No fw_meta on either bank → never OTA'd → factory-fresh.
        let flash_state = if active_meta.is_none() && previous_meta.is_none() {
            FlashState::Initial
        } else if committed {
            FlashState::Committed
        } else {
            FlashState::Activated
        };

        Ok(Some(ActivationState {
            // Static capability — A/B banks always exist and rollback_install
            // can flip the symlink back. Whether rollback is meaningful right
            // now is a state-machine concern caught by rollback_install itself.
            // Matches VmBackend's pattern of reporting config.supports_rollback.
            supports_rollback: true,
            state: flash_state,
            active_version: if version.is_empty() {
                None
            } else {
                Some(version)
            },
            previous_version: None,
        }))
    }

    async fn restart(&self) -> MachineResult<()> {
        tracing::warn!("app: restart requested — triggering host reboot");
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
            "bank": format!("{bank:?}"),
            "trial": trial,
        });
        Ok(RuntimeState {
            status: RuntimeStatus::Running,
            detail,
        })
    }
}
