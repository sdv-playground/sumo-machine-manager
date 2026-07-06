use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use machine_mgr::{
    Capabilities, Component, EnvelopeStream, FlashId, FlashSession, FlashStatus, MachineError,
    MachineResult,
};

use crate::manifest_provider::ManifestProvider;

const CONTAINER_IMAGE_COMPONENT: &str = "container_image";

enum InstallTarget {
    Vm,
    ContainerImage,
}

struct ActiveInstall {
    target: InstallTarget,
    id: FlashId,
}

pub struct AppInstallRouterComponent {
    vm_id: String,
    vm: Arc<dyn Component>,
    container_image: Arc<dyn Component>,
    manifest_provider: Arc<dyn ManifestProvider>,
    active_install: Mutex<Option<ActiveInstall>>,
}

impl AppInstallRouterComponent {
    pub fn new(
        vm_id: impl Into<String>,
        vm: Arc<dyn Component>,
        container_image: Arc<dyn Component>,
        manifest_provider: Arc<dyn ManifestProvider>,
    ) -> Self {
        Self {
            vm_id: vm_id.into(),
            vm,
            container_image,
            manifest_provider,
            active_install: Mutex::new(None),
        }
    }

    fn active_component(&self) -> MachineResult<Arc<dyn Component>> {
        match self
            .active_install
            .lock()
            .unwrap()
            .as_ref()
            .map(|a| &a.target)
        {
            Some(InstallTarget::Vm) => Ok(self.vm.clone()),
            Some(InstallTarget::ContainerImage) => Ok(self.container_image.clone()),
            None => Err(MachineError::UnknownFlashSession(
                "no active app install route".into(),
            )),
        }
    }

    fn active_id(&self) -> MachineResult<FlashId> {
        self.active_install
            .lock()
            .unwrap()
            .as_ref()
            .map(|a| a.id.clone())
            .ok_or_else(|| MachineError::UnknownFlashSession("no active app install route".into()))
    }

    async fn select_component(&self, manifest: &[u8]) -> MachineResult<Arc<dyn Component>> {
        let target = if self.is_valid_container_image_manifest_for_vm(manifest)? {
            InstallTarget::ContainerImage
        } else {
            InstallTarget::Vm
        };
        let component = match target {
            InstallTarget::Vm => self.vm.clone(),
            InstallTarget::ContainerImage => self.container_image.clone(),
        };
        let session = component.start_install().await?;
        *self.active_install.lock().unwrap() = Some(ActiveInstall {
            target,
            id: session.id,
        });
        Ok(component)
    }

    fn is_valid_container_image_manifest_for_vm(&self, bytes: &[u8]) -> MachineResult<bool> {
        if !is_container_image_manifest_for_vm(bytes, &self.vm_id)? {
            return Ok(false);
        }

        self.manifest_provider
            .validate_header_only(bytes, 0)
            .map_err(|e| {
                MachineError::ManifestInvalid(format!("container_image validation: {e}"))
            })?;
        Ok(true)
    }
}

#[async_trait]
impl Component for AppInstallRouterComponent {
    fn id(&self) -> &str {
        self.vm.id()
    }

    fn capabilities(&self) -> &Capabilities {
        self.vm.capabilities()
    }

    async fn start_install(&self) -> MachineResult<FlashSession> {
        self.vm.authorize_install().await?;
        *self.active_install.lock().unwrap() = None;
        Ok(FlashSession {
            id: FlashId::new(format!("{}-install", self.vm_id)),
            target_bank: None,
            max_chunk_size: 16 * 1024 * 1024,
        })
    }

    async fn upload_envelope(
        &self,
        _id: &FlashId,
        stream: EnvelopeStream,
    ) -> MachineResult<String> {
        let active = self.active_install.lock().unwrap().is_some();
        if active {
            let active_id = self.active_id()?;
            return self
                .active_component()?
                .upload_envelope(&active_id, stream)
                .await;
        }

        let manifest = collect_first_upload(stream).await?;
        let component = self.select_component(&manifest).await?;
        let active_id = self.active_id()?;
        component
            .upload_envelope(&active_id, bytes_to_stream(manifest))
            .await
    }

    async fn finalize_install(&self, _id: &FlashId) -> MachineResult<()> {
        self.active_component()?
            .finalize_install(&self.active_id()?)
            .await
    }

    async fn commit_install(&self, _id: &FlashId) -> MachineResult<()> {
        self.active_component()?
            .commit_install(&self.active_id()?)
            .await
    }

    async fn rollback_install(&self, _id: &FlashId) -> MachineResult<()> {
        self.active_component()?
            .rollback_install(&self.active_id()?)
            .await
    }

    async fn abort_install(&self, _id: &FlashId) -> MachineResult<()> {
        self.active_component()?
            .abort_install(&self.active_id()?)
            .await
    }

    async fn install_status(&self, _id: &FlashId) -> MachineResult<FlashStatus> {
        self.active_component()?
            .install_status(&self.active_id()?)
            .await
    }

    async fn activation_state(&self) -> MachineResult<Option<machine_mgr::ActivationState>> {
        self.vm.activation_state().await
    }

    async fn list_dids(
        &self,
        filter: &machine_mgr::DidFilter,
    ) -> MachineResult<Vec<machine_mgr::component::DidEntry>> {
        self.vm.list_dids(filter).await
    }

    async fn read_did(&self, key: u16, kind: machine_mgr::DidKind) -> MachineResult<Bytes> {
        self.vm.read_did(key, kind).await
    }

    async fn write_did(
        &self,
        key: u16,
        kind: machine_mgr::DidKind,
        value: &[u8],
    ) -> MachineResult<()> {
        self.vm.write_did(key, kind, value).await
    }

    async fn read_dtcs(
        &self,
        filter: &machine_mgr::DtcFilter,
    ) -> MachineResult<Vec<machine_mgr::Fault>> {
        self.vm.read_dtcs(filter).await
    }

    async fn clear_dtcs(
        &self,
        group: Option<u32>,
    ) -> MachineResult<machine_mgr::ClearFaultsResult> {
        self.vm.clear_dtcs(group).await
    }

    async fn start(&self) -> MachineResult<()> {
        self.vm.start().await
    }
}

fn is_container_image_manifest_for_vm(bytes: &[u8], vm_id: &str) -> MachineResult<bool> {
    let Ok(envelope) = sumo_codec::decode::decode_envelope(bytes) else {
        return Ok(false);
    };
    let manifest = sumo_onboard::manifest::Manifest { envelope };
    Ok(manifest
        .component_id(0)
        .is_some_and(|segments| match segments {
            [vm, component, ..] => {
                vm.as_slice() == vm_id.as_bytes()
                    && component.as_slice() == CONTAINER_IMAGE_COMPONENT.as_bytes()
            }
            _ => false,
        }))
}

async fn collect_first_upload(mut stream: EnvelopeStream) -> MachineResult<Vec<u8>> {
    let mut data = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| MachineError::Internal(format!("install route read: {e}")))?;
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

fn bytes_to_stream(bytes: Vec<u8>) -> EnvelopeStream {
    Box::pin(futures::stream::once(async move {
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(Bytes::from(bytes))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::manifest_provider::{ManifestError, ManifestType, ValidatedFirmware};
    use crate::ota::ImageMeta;
    use async_trait::async_trait;
    use machine_mgr::{FlashCaps, LifecycleCaps, ResetKind};
    use nv_store::types::BankSet;
    use sumo_offboard::keygen::{self, ES256};
    use sumo_offboard::ImageManifestBuilder;

    struct StubComponent {
        id: &'static str,
        authorize_result: MachineResult<()>,
        start_count: AtomicUsize,
        capabilities: Capabilities,
    }

    impl StubComponent {
        fn new(id: &'static str, authorize_result: MachineResult<()>) -> Self {
            Self {
                id,
                authorize_result,
                start_count: AtomicUsize::new(0),
                capabilities: Capabilities {
                    did_store: false,
                    flash: Some(FlashCaps {
                        dual_bank: false,
                        supports_rollback: false,
                        supports_trial_boot: false,
                        abortable_after_finalize: false,
                        reset_kind: ResetKind::Local,
                    }),
                    lifecycle: Some(LifecycleCaps {
                        restartable: false,
                        has_runtime_state: false,
                    }),
                    hsm: None,
                    dtcs: false,
                    clear_dtcs: false,
                },
            }
        }
    }

    #[async_trait]
    impl Component for StubComponent {
        fn id(&self) -> &str {
            self.id
        }

        fn capabilities(&self) -> &Capabilities {
            &self.capabilities
        }

        async fn authorize_install(&self) -> MachineResult<()> {
            self.authorize_result.clone()
        }

        async fn start_install(&self) -> MachineResult<FlashSession> {
            self.start_count.fetch_add(1, Ordering::SeqCst);
            Ok(FlashSession {
                id: FlashId::new(self.id),
                target_bank: None,
                max_chunk_size: 0,
            })
        }

        async fn upload_envelope(
            &self,
            _id: &FlashId,
            _stream: EnvelopeStream,
        ) -> MachineResult<String> {
            Ok(format!("{}-upload", self.id))
        }
    }

    struct RejectingManifestProvider;

    impl ManifestProvider for RejectingManifestProvider {
        fn validate(
            &self,
            _data: &[u8],
            _min_security_ver: u32,
        ) -> Result<ValidatedFirmware, ManifestError> {
            Err(ManifestError::SignatureInvalid("test rejection".into()))
        }
    }

    struct AcceptingManifestProvider;

    impl ManifestProvider for AcceptingManifestProvider {
        fn validate(
            &self,
            _data: &[u8],
            _min_security_ver: u32,
        ) -> Result<ValidatedFirmware, ManifestError> {
            Ok(ValidatedFirmware {
                bank_set: BankSet::Vm2,
                manifest_type: ManifestType::Firmware,
                image_meta: ImageMeta::default(),
                image_data: Vec::new(),
                version_display: "1.0.0".into(),
                image_sha256: None,
                image_size: None,
                raw_envelope: None,
                streamed_files: Vec::new(),
            })
        }
    }

    fn container_image_manifest() -> Vec<u8> {
        let signing_key = keygen::generate_signing_key(ES256).unwrap();
        ImageManifestBuilder::new()
            .signing_time(1_700_000_000)
            .component_id(vec!["vm2".into(), "container_image".into()])
            .sequence_number(1)
            .payload_digest(&[0u8; 32], 0)
            .payload_uri("#container-image".into())
            .security_version(1)
            .build(&signing_key)
            .unwrap()
    }

    #[tokio::test]
    async fn start_install_requires_vm_flash_authorization() {
        let vm = Arc::new(StubComponent::new(
            "vm2",
            Err(MachineError::PolicyRejected("locked".into())),
        ));
        let container = Arc::new(StubComponent::new("container_image", Ok(())));
        let router = AppInstallRouterComponent::new(
            "vm2",
            vm,
            container,
            Arc::new(AcceptingManifestProvider),
        );

        let err = router.start_install().await.unwrap_err();
        assert!(err.to_string().contains("locked"), "{err}");
    }

    #[tokio::test]
    async fn container_route_rejects_manifest_that_provider_does_not_validate() {
        let vm = Arc::new(StubComponent::new("vm2", Ok(())));
        let container = Arc::new(StubComponent::new("container_image", Ok(())));
        let router = AppInstallRouterComponent::new(
            "vm2",
            vm,
            container.clone(),
            Arc::new(RejectingManifestProvider),
        );

        router.start_install().await.unwrap();
        let err = router
            .upload_envelope(
                &FlashId::new("vm2-install"),
                bytes_to_stream(container_image_manifest()),
            )
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("container_image validation"),
            "{err}"
        );
        assert_eq!(container.start_count.load(Ordering::SeqCst), 0);
    }
}
