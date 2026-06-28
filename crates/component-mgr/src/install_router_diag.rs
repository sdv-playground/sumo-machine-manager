//! `InstallRouterDiag` — narrow install-time routing wrapper.
//!
//! `ComponentBackend` (`backend.rs`) is already a complete, standalone
//! `DiagnosticBackend` — it owns the data engine (DIDs, the
//! `x-sumo-installed-manifest` intercept, the F187–F19E identity overlay,
//! health DIDs), the fault/DTC store, the full OTA flash lifecycle, and the
//! modes. So wherever a component's install/flash lifecycle IS the engine's,
//! the engine is wired straight into SOVD with no wrapper.
//!
//! This wrapper exists for the two cases where install/flash must run through a
//! `Component` that is NOT the data engine:
//!
//! * **vm2** — a SUIT envelope on its `/updates` wire may target the VM bank
//!   set OR the in-VM container image; `AppInstallRouterComponent` makes the
//!   container-vs-VM routing decision (`sovd_main` / the host's vm2 path).
//! * **the self-updating `app` slot** — `app_mgr::AppComponent` has its own A/B
//!   symlink-flip lifecycle, distinct from the VM bank flow (component-factory
//!   `app` branch).
//!
//! In both cases this wrapper intercepts ONLY the install/flash methods and
//! routes them through the `router` `Component`; EVERY other method — data,
//! faults, modes, reset, package catalog, sub-entities — delegates to the
//! `engine` (the `ComponentBackend`), so the data 404s the old round-trip
//! adapter caused can't recur.
//!
//! The install/flash bodies are lifted verbatim from the retired
//! `ComponentDiagBackend` so the OTA flow is byte-for-byte unchanged — the
//! `NotSupported` arms fall back to the engine exactly as before.

use std::sync::Arc;

use async_trait::async_trait;

use machine_mgr::{Component, MachineError};

use sovd_core::backend::*;
use sovd_core::error::{BackendError, BackendResult};
use sovd_core::models::*;
use sovd_core::PackageStream;

/// Routes the install/flash methods through an install-router `Component`
/// (vm2's `AppInstallRouterComponent`) and delegates everything else to the
/// `engine` (`ComponentBackend`).
pub struct InstallRouterDiag {
    router: Arc<dyn Component>,
    engine: Arc<dyn DiagnosticBackend>,
}

impl InstallRouterDiag {
    pub fn new(router: Arc<dyn Component>, engine: Arc<dyn DiagnosticBackend>) -> Self {
        Self { router, engine }
    }

    /// Wire-side upload (`receive_package*`). Session lifecycle is owned by the
    /// router `Component` impl — this wrapper is stateless. The `id` is a
    /// sentinel the router ignores (it tracks one in-flight session
    /// internally). The returned String is the per-upload identifier the impl
    /// chose to expose on the wire.
    async fn upload_via_install_pipeline(
        &self,
        stream: machine_mgr::EnvelopeStream,
    ) -> BackendResult<String> {
        let id = machine_mgr::FlashId::new("");
        match self.router.upload_envelope(&id, stream).await {
            Ok(s) => Ok(s),
            Err(MachineError::NotSupported(_)) => Err(BackendError::NotSupported(
                "component does not support install pipeline".into(),
            )),
            Err(e) => Err(map_machine_error(e)),
        }
    }
}

#[async_trait]
impl DiagnosticBackend for InstallRouterDiag {
    // -----------------------------------------------------------------
    // Identity / capabilities — delegated to the engine.
    // -----------------------------------------------------------------

    fn entity_info(&self) -> &EntityInfo {
        self.engine.entity_info()
    }

    fn capabilities(&self) -> &Capabilities {
        self.engine.capabilities()
    }

    fn update_shape(&self) -> &'static str {
        self.engine.update_shape()
    }

    // -----------------------------------------------------------------
    // Data — delegated to the engine (the single authority that owns the
    // DID registry, identity overlay, and x-sumo-installed-manifest).
    // -----------------------------------------------------------------

    async fn list_parameters(&self) -> BackendResult<Vec<ParameterInfo>> {
        self.engine.list_parameters().await
    }

    async fn read_data(&self, param_ids: &[String]) -> BackendResult<Vec<DataValue>> {
        self.engine.read_data(param_ids).await
    }

    async fn write_data(&self, param_id: &str, value: &[u8]) -> BackendResult<()> {
        self.engine.write_data(param_id, value).await
    }

    async fn read_raw_did(&self, did: u16) -> BackendResult<Vec<u8>> {
        self.engine.read_raw_did(did).await
    }

    async fn write_raw_did(&self, did: u16, data: &[u8]) -> BackendResult<()> {
        self.engine.write_raw_did(did, data).await
    }

    async fn define_data_identifier(
        &self,
        ddid: u16,
        sources: &[(u16, u8, u8)],
    ) -> BackendResult<()> {
        self.engine.define_data_identifier(ddid, sources).await
    }

    async fn clear_data_identifier(&self, ddid: u16) -> BackendResult<()> {
        self.engine.clear_data_identifier(ddid).await
    }

    async fn ecu_reset(&self, reset_type: u8) -> BackendResult<Option<u8>> {
        self.engine.ecu_reset(reset_type).await
    }

    // Entity status (§7.19.2: ready/notReady + x-sumo-runtime boot_count) —
    // delegated to the engine, which owns the heartbeat + NV boot counter.
    async fn read_entity_status(&self) -> BackendResult<EntityStatusBody> {
        self.engine.read_entity_status().await
    }

    // -----------------------------------------------------------------
    // Faults — delegated to the engine (NV-backed DTC store).
    // -----------------------------------------------------------------

    async fn get_faults(&self, filter: Option<&FaultFilter>) -> BackendResult<FaultsResult> {
        self.engine.get_faults(filter).await
    }

    async fn get_fault_detail(&self, fault_id: &str) -> BackendResult<Fault> {
        self.engine.get_fault_detail(fault_id).await
    }

    async fn clear_faults(&self, group: Option<u32>) -> BackendResult<ClearFaultsResult> {
        self.engine.clear_faults(group).await
    }

    // -----------------------------------------------------------------
    // Operations — delegated to the engine.
    // -----------------------------------------------------------------

    async fn list_operations(&self) -> BackendResult<Vec<OperationInfo>> {
        self.engine.list_operations().await
    }

    async fn start_operation(
        &self,
        operation_id: &str,
        params: &[u8],
    ) -> BackendResult<OperationExecution> {
        self.engine.start_operation(operation_id, params).await
    }

    // -----------------------------------------------------------------
    // Package catalog / describe — delegated to the engine, which owns the
    // SUIT-aware describe cache + the stored-package store.
    // -----------------------------------------------------------------

    async fn describe_update_package(
        &self,
        ctx: &UpdatePackageContext<'_>,
    ) -> BackendResult<UpdatePackageDescriptor> {
        self.engine.describe_update_package(ctx).await
    }

    async fn list_packages(&self) -> BackendResult<Vec<PackageInfo>> {
        self.engine.list_packages().await
    }

    async fn get_package(&self, package_id: &str) -> BackendResult<PackageInfo> {
        self.engine.get_package(package_id).await
    }

    async fn verify_package(&self, package_id: &str) -> BackendResult<VerifyResult> {
        self.engine.verify_package(package_id).await
    }

    async fn verify_part(&self, file_id: &str, expected_sha256: &str) -> BackendResult<()> {
        self.engine.verify_part(file_id, expected_sha256).await
    }

    async fn delete_package(&self, package_id: &str) -> BackendResult<()> {
        self.engine.delete_package(package_id).await
    }

    // -----------------------------------------------------------------
    // Install / flash — INTERCEPTED, routed through the install router so
    // vm2's container-vs-VM decision still happens. Bodies are verbatim from
    // the retired ComponentDiagBackend; the `NotSupported` arms fall back to
    // the engine exactly as before.
    // -----------------------------------------------------------------

    // Single-shot upload: wrap bytes as a one-element stream and route through
    // the router's upload_envelope. Streams are not replayable, so we can't
    // fall back mid-upload — if the router declines, surface the error.
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

    async fn start_flash(&self) -> BackendResult<String> {
        match self.router.start_install().await {
            Ok(session) => Ok(session.id.to_string()),
            Err(MachineError::NotSupported(_)) => self.engine.start_flash().await,
            Err(e) => Err(map_machine_error(e)),
        }
    }

    async fn get_flash_status(&self, transfer_id: &str) -> BackendResult<FlashStatus> {
        let id = machine_mgr::FlashId::new(transfer_id);
        match self.router.install_status(&id).await {
            Ok(status) => Ok(status),
            Err(MachineError::NotSupported(_)) => self.engine.get_flash_status(transfer_id).await,
            Err(e) => Err(map_machine_error(e)),
        }
    }

    async fn finalize_flash(&self) -> BackendResult<()> {
        let id = machine_mgr::FlashId::new("");
        match self.router.finalize_install(&id).await {
            Ok(()) => Ok(()),
            Err(MachineError::NotSupported(_)) => self.engine.finalize_flash().await,
            Err(e) => Err(map_machine_error(e)),
        }
    }

    // validate / invalidate / activate are not routed through the Component
    // trait — machine-mgr has no equivalent ops. Delegate to the engine's
    // ComponentBackend implementation (same as ComponentDiagBackend did).
    async fn validate(&self) -> BackendResult<()> {
        self.engine.validate().await
    }

    async fn invalidate(&self) -> BackendResult<()> {
        self.engine.invalidate().await
    }

    async fn activate(&self) -> BackendResult<()> {
        self.engine.activate().await
    }

    async fn list_flash_transfers(&self) -> BackendResult<Vec<FlashStatus>> {
        self.engine.list_flash_transfers().await
    }

    async fn get_activation_state(&self) -> BackendResult<ActivationState> {
        match self.router.activation_state().await {
            Ok(Some(state)) => Ok(state),
            // Router declines to report — fall back to the engine.
            Ok(None) | Err(MachineError::NotSupported(_)) => {
                self.engine.get_activation_state().await
            }
            Err(e) => Err(map_machine_error(e)),
        }
    }

    // SOVD's commit_flash / rollback_flash take no transfer_id (one in-flight
    // session per component on the wire). The router's API takes a `&FlashId`
    // for future multi-session support; today it ignores the id, so the
    // sentinel is harmless.
    async fn commit_flash(&self) -> BackendResult<()> {
        let id = machine_mgr::FlashId::new("");
        match self.router.commit_install(&id).await {
            Ok(()) => Ok(()),
            Err(MachineError::NotSupported(_)) => self.engine.commit_flash().await,
            Err(e) => Err(map_machine_error(e)),
        }
    }

    async fn rollback_flash(&self) -> BackendResult<()> {
        let id = machine_mgr::FlashId::new("");
        match self.router.rollback_install(&id).await {
            Ok(()) => Ok(()),
            Err(MachineError::NotSupported(_)) => self.engine.rollback_flash().await,
            Err(e) => Err(map_machine_error(e)),
        }
    }

    async fn abort_flash(&self, transfer_id: &str) -> BackendResult<()> {
        let id = machine_mgr::FlashId::new(transfer_id);
        match self.router.abort_install(&id).await {
            Ok(()) => Ok(()),
            Err(MachineError::NotSupported(_)) => self.engine.abort_flash(transfer_id).await,
            Err(e) => Err(map_machine_error(e)),
        }
    }

    // -----------------------------------------------------------------
    // Modes — delegated to the engine.
    // -----------------------------------------------------------------

    async fn get_session_mode(&self) -> BackendResult<SessionMode> {
        self.engine.get_session_mode().await
    }

    async fn set_session_mode(&self, session: &str) -> BackendResult<SessionMode> {
        self.engine.set_session_mode(session).await
    }

    async fn get_security_mode(&self) -> BackendResult<SecurityMode> {
        self.engine.get_security_mode().await
    }

    async fn set_security_mode(
        &self,
        value: &str,
        key: Option<&[u8]>,
    ) -> BackendResult<SecurityMode> {
        self.engine.set_security_mode(value, key).await
    }

    async fn get_link_mode(&self) -> BackendResult<LinkMode> {
        self.engine.get_link_mode().await
    }

    async fn set_link_mode(
        &self,
        action: &str,
        baud_rate_id: Option<&str>,
        baud_rate: Option<u32>,
    ) -> BackendResult<LinkControlResult> {
        self.engine
            .set_link_mode(action, baud_rate_id, baud_rate)
            .await
    }

    // -----------------------------------------------------------------
    // Logs / outputs / sub-entities / software-info — delegated to the engine
    // (it carries the trait defaults; delegating keeps one authority).
    // -----------------------------------------------------------------

    async fn get_logs(&self, filter: &LogFilter) -> BackendResult<Vec<LogEntry>> {
        self.engine.get_logs(filter).await
    }

    async fn get_log(&self, log_id: &str) -> BackendResult<LogEntry> {
        self.engine.get_log(log_id).await
    }

    async fn get_log_content(&self, log_id: &str) -> BackendResult<Vec<u8>> {
        self.engine.get_log_content(log_id).await
    }

    async fn delete_log(&self, log_id: &str) -> BackendResult<()> {
        self.engine.delete_log(log_id).await
    }

    async fn list_outputs(&self) -> BackendResult<Vec<OutputInfo>> {
        self.engine.list_outputs().await
    }

    async fn get_output(&self, output_id: &str) -> BackendResult<OutputDetail> {
        self.engine.get_output(output_id).await
    }

    async fn control_output(
        &self,
        output_id: &str,
        action: IoControlAction,
        value: Option<serde_json::Value>,
    ) -> BackendResult<IoControlResult> {
        self.engine.control_output(output_id, action, value).await
    }

    async fn list_sub_entities(&self) -> BackendResult<Vec<EntityInfo>> {
        self.engine.list_sub_entities().await
    }

    async fn get_sub_entity(&self, id: &str) -> BackendResult<Arc<dyn DiagnosticBackend>> {
        self.engine.get_sub_entity(id).await
    }

    async fn get_software_info(&self) -> BackendResult<SoftwareInfo> {
        self.engine.get_software_info().await
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
