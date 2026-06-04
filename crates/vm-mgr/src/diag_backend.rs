//! `ComponentDiagBackend` — adapts a `machine-mgr::Component` into a
//! `sovd-core::DiagnosticBackend`.
//!
//! Migration adapter: it wraps both a `Component` (the new path) and a
//! fallback `DiagnosticBackend` (today's `VmBackend`). Method bodies that have
//! been wired through `Component` route there; the rest fall through to the
//! fallback. As more `Component` methods are wired across subsequent PRs, the
//! fallback becomes vestigial and can eventually be dropped.
//!
//! This file is the *only* place where machine-mgr semantics get translated
//! into the SOVD wire format. Everything outside of it stays SOVD-shaped.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;

use machine_mgr::{Component, DidFilter, DidKind, DtcFilter, MachineError};

use sovd_core::backend::*;
use sovd_core::error::{BackendError, BackendResult};
use sovd_core::models::*;
use sovd_core::PackageStream;

use crate::backend::{did_value_to_json, resolve_param, DidEntry};
use crate::did;

/// Wraps a `Component` as a `DiagnosticBackend`.
///
/// `entity_info` and `capabilities` are delegated to the fallback because
/// those are SOVD-wire shapes and today live on `VmBackend`. Once `Component`
/// owns the SOVD-side `EntityInfo`/`Capabilities` (PR 4 work), the fallback
/// can be retired.
pub struct ComponentDiagBackend {
    component: Arc<dyn Component>,
    fallback: Arc<dyn DiagnosticBackend>,
}

impl ComponentDiagBackend {
    pub fn new(component: Arc<dyn Component>, fallback: Arc<dyn DiagnosticBackend>) -> Self {
        Self {
            component,
            fallback,
        }
    }

    /// Wire-side upload (`receive_package*`). Session lifecycle is owned by
    /// the `Component` impl — the adapter is stateless. The `id` we pass is
    /// a sentinel that today's `VmBackendComponent` ignores (it tracks one
    /// in-flight session per component internally). The returned String is
    /// the per-upload identifier the impl chose to expose on the wire.
    async fn upload_via_install_pipeline(
        &self,
        stream: machine_mgr::EnvelopeStream,
    ) -> BackendResult<String> {
        let id = machine_mgr::FlashId::new("");
        match self.component.upload_envelope(&id, stream).await {
            Ok(s) => Ok(s),
            Err(MachineError::NotSupported(_)) => Err(BackendError::NotSupported(
                "component does not support install pipeline".into(),
            )),
            Err(e) => Err(map_machine_error(e)),
        }
    }
}

#[async_trait]
impl DiagnosticBackend for ComponentDiagBackend {
    // -----------------------------------------------------------------
    // Identity — delegated to fallback (SOVD-wire shape lives there today)
    // -----------------------------------------------------------------

    fn entity_info(&self) -> &EntityInfo {
        self.fallback.entity_info()
    }

    fn capabilities(&self) -> &Capabilities {
        self.fallback.capabilities()
    }

    /// F.D5: delegate to the underlying VmBackend so the campaign
    /// coordinator on the SOVD wire sees the right shape regardless of
    /// whether it reaches the Component-trait path or the fallback.
    fn update_shape(&self) -> &'static str {
        self.fallback.update_shape()
    }

    // -----------------------------------------------------------------
    // Faults — wired through Component
    // -----------------------------------------------------------------

    async fn get_faults(&self, _filter: Option<&FaultFilter>) -> BackendResult<FaultsResult> {
        match self.component.read_dtcs(&DtcFilter::default()).await {
            Ok(faults) => Ok(FaultsResult {
                faults,
                status_availability_mask: None,
            }),
            Err(MachineError::NotSupported(_)) => self.fallback.get_faults(_filter).await,
            Err(e) => Err(map_machine_error(e)),
        }
    }

    async fn clear_faults(&self, group: Option<u32>) -> BackendResult<ClearFaultsResult> {
        match self.component.clear_dtcs(group).await {
            Ok(res) => Ok(res),
            Err(MachineError::NotSupported(_)) => self.fallback.clear_faults(group).await,
            Err(e) => Err(map_machine_error(e)),
        }
    }

    // -----------------------------------------------------------------
    // Everything else — pass-through to fallback (wired in subsequent PRs)
    // -----------------------------------------------------------------

    async fn list_parameters(&self) -> BackendResult<Vec<ParameterInfo>> {
        let dids = match self.component.list_dids(&DidFilter::default()).await {
            Ok(dids) => dids,
            Err(MachineError::NotSupported(_)) => return self.fallback.list_parameters().await,
            Err(e) => return Err(map_machine_error(e)),
        };

        let entity_id = self.entity_info().id.clone();
        let params = dids
            .into_iter()
            .map(|d| {
                // Look up wire data_type from the static registry; runtime
                // DIDs that aren't in the registry default to "bytes".
                let data_type = crate::backend::DID_REGISTRY
                    .iter()
                    .find(|r| r.did == d.key)
                    .map(|r| r.data_type.to_string())
                    .unwrap_or_else(|| "bytes".to_string());

                ParameterInfo {
                    id: d.id.clone(),
                    name: d.name,
                    description: None,
                    unit: None,
                    data_type: Some(data_type),
                    read_only: !d.writable,
                    href: format!("/vehicle/v1/components/{entity_id}/data/{}", d.id),
                    did: Some(format!("{:04X}", d.key)),
                    category: Some(DataCategory::from_did(d.key)),
                }
            })
            .collect();
        Ok(params)
    }

    // Routes per-DID: NV-backed DIDs go through `Component::read_did`; the live
    // health DIDs (vm-service queries) still need the fallback. If `Component`
    // ever returns `NotSupported` we fall through too.
    async fn read_data(&self, param_ids: &[String]) -> BackendResult<Vec<DataValue>> {
        let mut values = Vec::with_capacity(param_ids.len());
        for param_id in param_ids {
            let (did_num, reg) = resolve_param(param_id)
                .ok_or_else(|| BackendError::ParameterNotFound(param_id.clone()))?;

            if is_health_did(did_num) {
                let mut single = self
                    .fallback
                    .read_data(std::slice::from_ref(param_id))
                    .await?;
                if let Some(v) = single.pop() {
                    values.push(v);
                }
                continue;
            }

            match self.component.read_did(did_num, DidKind::Runtime).await {
                Ok(bytes) => values.push(make_data_value(param_id, did_num, reg, &bytes)),
                Err(MachineError::NotSupported(_)) => {
                    let mut single = self
                        .fallback
                        .read_data(std::slice::from_ref(param_id))
                        .await?;
                    if let Some(v) = single.pop() {
                        values.push(v);
                    }
                }
                Err(MachineError::NotFound(_)) => {
                    return Err(BackendError::ParameterNotFound(param_id.clone()));
                }
                Err(e) => return Err(map_machine_error(e)),
            }
        }
        Ok(values)
    }

    async fn write_data(&self, param_id: &str, value: &[u8]) -> BackendResult<()> {
        let (did_num, reg) = resolve_param(param_id)
            .ok_or_else(|| BackendError::ParameterNotFound(param_id.to_string()))?;

        if let Some(r) = reg {
            if !r.writable {
                return Err(BackendError::InvalidRequest(format!(
                    "DID 0x{:04X} ({}) is read-only",
                    did_num, r.name
                )));
            }
        }

        match self
            .component
            .write_did(did_num, DidKind::Runtime, value)
            .await
        {
            Ok(()) => Ok(()),
            Err(MachineError::NotSupported(_)) => self.fallback.write_data(param_id, value).await,
            Err(e) => Err(map_machine_error(e)),
        }
    }

    async fn list_operations(&self) -> BackendResult<Vec<OperationInfo>> {
        self.fallback.list_operations().await
    }

    async fn start_operation(
        &self,
        operation_id: &str,
        params: &[u8],
    ) -> BackendResult<OperationExecution> {
        self.fallback.start_operation(operation_id, params).await
    }

    // Single-shot upload: wrap bytes as a one-element stream and route
    // through Component::upload_envelope. Streams are not replayable, so we
    // can't fall back mid-upload — if Component declines, surface the error.
    async fn receive_package(&self, data: &[u8]) -> BackendResult<String> {
        let bytes = bytes::Bytes::copy_from_slice(data);
        let stream: machine_mgr::EnvelopeStream = Box::pin(futures::stream::once(async move {
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(bytes)
        }));
        self.upload_via_install_pipeline(stream).await
    }

    async fn receive_package_stream(
        &self,
        stream: PackageStream,
        _content_length: Option<u64>,
    ) -> BackendResult<String> {
        self.upload_via_install_pipeline(stream).await
    }

    // GET /updates/{id} catalog detail (ISO 17978-3 §7.18.3 Table 261).
    // SUIT-aware enrichment lives on the wrapped VmBackend (it owns the
    // manifest describe-cache + the SOVD entity_info); forward there so the
    // wire sees the enriched descriptor regardless of which path served the
    // upload. Falls back to the format-agnostic default inside VmBackend
    // when the manifest can't be located/parsed.
    async fn describe_update_package(
        &self,
        ctx: &UpdatePackageContext<'_>,
    ) -> BackendResult<UpdatePackageDescriptor> {
        self.fallback.describe_update_package(ctx).await
    }

    async fn list_packages(&self) -> BackendResult<Vec<PackageInfo>> {
        self.fallback.list_packages().await
    }

    async fn get_package(&self, package_id: &str) -> BackendResult<PackageInfo> {
        self.fallback.get_package(package_id).await
    }

    async fn verify_package(&self, package_id: &str) -> BackendResult<VerifyResult> {
        self.fallback.verify_package(package_id).await
    }

    async fn verify_part(&self, file_id: &str, expected_sha256: &str) -> BackendResult<()> {
        self.fallback.verify_part(file_id, expected_sha256).await
    }

    async fn delete_package(&self, package_id: &str) -> BackendResult<()> {
        self.fallback.delete_package(package_id).await
    }

    async fn start_flash(&self) -> BackendResult<String> {
        match self.component.start_install().await {
            Ok(session) => Ok(session.id.to_string()),
            Err(MachineError::NotSupported(_)) => self.fallback.start_flash().await,
            Err(e) => Err(map_machine_error(e)),
        }
    }

    async fn get_flash_status(&self, transfer_id: &str) -> BackendResult<FlashStatus> {
        let id = machine_mgr::FlashId::new(transfer_id);
        match self.component.install_status(&id).await {
            Ok(status) => Ok(status),
            Err(MachineError::NotSupported(_)) => self.fallback.get_flash_status(transfer_id).await,
            Err(e) => Err(map_machine_error(e)),
        }
    }

    async fn finalize_flash(&self) -> BackendResult<()> {
        let id = machine_mgr::FlashId::new("");
        match self.component.finalize_install(&id).await {
            Ok(()) => Ok(()),
            Err(MachineError::NotSupported(_)) => self.fallback.finalize_flash().await,
            Err(e) => Err(map_machine_error(e)),
        }
    }

    // validate / invalidate / activate are not (yet) routed through the
    // Component trait — machine-mgr has no equivalent ops. Delegate
    // directly to the legacy VmBackend implementation.
    async fn validate(&self) -> BackendResult<()> {
        self.fallback.validate().await
    }

    async fn invalidate(&self) -> BackendResult<()> {
        self.fallback.invalidate().await
    }

    async fn activate(&self) -> BackendResult<()> {
        self.fallback.activate().await
    }

    async fn list_flash_transfers(&self) -> BackendResult<Vec<FlashStatus>> {
        self.fallback.list_flash_transfers().await
    }

    async fn get_activation_state(&self) -> BackendResult<ActivationState> {
        match self.component.activation_state().await {
            Ok(Some(state)) => Ok(state),
            // Component declines to report — fall back to legacy path.
            Ok(None) | Err(MachineError::NotSupported(_)) => {
                self.fallback.get_activation_state().await
            }
            Err(e) => Err(map_machine_error(e)),
        }
    }

    // SOVD's commit_flash / rollback_flash take no transfer_id (one in-flight
    // session per component on the wire). Component's API takes a `&FlashId`
    // for future multi-session support; today's VmBackendComponent ignores
    // the id, so the sentinel is harmless.
    async fn commit_flash(&self) -> BackendResult<()> {
        let id = machine_mgr::FlashId::new("");
        match self.component.commit_install(&id).await {
            Ok(()) => Ok(()),
            Err(MachineError::NotSupported(_)) => self.fallback.commit_flash().await,
            Err(e) => Err(map_machine_error(e)),
        }
    }

    async fn rollback_flash(&self) -> BackendResult<()> {
        let id = machine_mgr::FlashId::new("");
        match self.component.rollback_install(&id).await {
            Ok(()) => Ok(()),
            Err(MachineError::NotSupported(_)) => self.fallback.rollback_flash().await,
            Err(e) => Err(map_machine_error(e)),
        }
    }

    async fn abort_flash(&self, transfer_id: &str) -> BackendResult<()> {
        let id = machine_mgr::FlashId::new(transfer_id);
        match self.component.abort_install(&id).await {
            Ok(()) => Ok(()),
            Err(MachineError::NotSupported(_)) => self.fallback.abort_flash(transfer_id).await,
            Err(e) => Err(map_machine_error(e)),
        }
    }

    // NOTE: ecu_reset is intentionally still on the fallback. `VmBackend`
    // returns `Ok(None)` for the boot component (meaning "reset deferred,
    // requires manual reboot") and `Ok(Some(reset_type))` for everything
    // else. `Component::restart` returns `()` so it can't carry that
    // distinction. Wiring this needs `Component::restart` to either return
    // `Option<u8>` (wire-shape leaking) or expose a "reset is deferred"
    // capability. Deferred to a follow-up.
    async fn ecu_reset(&self, reset_type: u8) -> BackendResult<Option<u8>> {
        self.fallback.ecu_reset(reset_type).await
    }

    async fn get_session_mode(&self) -> BackendResult<SessionMode> {
        self.fallback.get_session_mode().await
    }

    async fn set_session_mode(&self, session: &str) -> BackendResult<SessionMode> {
        self.fallback.set_session_mode(session).await
    }

    async fn get_security_mode(&self) -> BackendResult<SecurityMode> {
        self.fallback.get_security_mode().await
    }

    async fn set_security_mode(
        &self,
        value: &str,
        key: Option<&[u8]>,
    ) -> BackendResult<SecurityMode> {
        self.fallback.set_security_mode(value, key).await
    }
}

fn is_health_did(did_num: u16) -> bool {
    matches!(did_num, did::DID_GUEST_STATE | did::DID_HEARTBEAT_SEQ)
}

fn make_data_value(
    param_id: &str,
    did_num: u16,
    reg: Option<&DidEntry>,
    bytes: &[u8],
) -> DataValue {
    let value = did_value_to_json(did_num, bytes, reg);
    let raw_hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let name = reg.map(|r| r.name).unwrap_or(param_id);
    DataValue {
        id: param_id.to_string(),
        name: name.to_string(),
        value,
        unit: None,
        timestamp: Utc::now(),
        raw: Some(raw_hex),
        did: Some(format!("{:04X}", did_num)),
        length: Some(bytes.len()),
    }
}

fn map_machine_error(e: MachineError) -> BackendError {
    match e {
        MachineError::NotSupported(op) => BackendError::NotSupported(op.to_string()),
        MachineError::NotFound(s) => BackendError::EntityNotFound(s),
        MachineError::InvalidArgument(s) => BackendError::InvalidRequest(s),
        MachineError::PolicyRejected(s) => BackendError::InvalidRequest(s),
        MachineError::Busy(s) => BackendError::Busy(s),
        MachineError::ManifestInvalid(s) => BackendError::InvalidRequest(s),
        // F.D3 dispatcher: target mismatch maps to HTTP 415.
        MachineError::WrongTarget(s) => BackendError::UnsupportedMediaType(s),
        MachineError::UnknownFlashSession(s) => BackendError::InvalidRequest(s),
        MachineError::Storage(s) => BackendError::Internal(s),
        MachineError::Internal(s) => BackendError::Internal(s),
    }
}
