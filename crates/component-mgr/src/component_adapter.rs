//! Adapter — exposes a `ComponentBackend` instance through the `machine-mgr::Component`
//! trait. Diagserver does not yet use this; PR 3 wires it in.
//!
//! Each `ComponentBackend` is already bound to a single `BankSet` (one component), so
//! the wrapper is 1:1 — no per-component routing logic.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use sovd_core::error::BackendError;
use sovd_core::DiagnosticBackend;

use nv_store::block::BlockDevice;

use machine_mgr::component::DidEntry;
use machine_mgr::{
    ActivationState, Capabilities, ClearFaultsResult, Component, Csr, DidFilter, DidKind,
    DtcFilter, EnvelopeStream, Fault, FlashCaps, FlashId, FlashSession, FlashStatus, HsmCaps,
    KeyDescriptor, KeyInventory, LifecycleCaps, MachineError, MachineResult, RuntimeState,
    RuntimeStatus, SlotKind,
};

use crate::backend::{ComponentBackend, DID_REGISTRY};
use crate::did;

pub struct ComponentAdapter<D: BlockDevice + Send + 'static> {
    inner: Arc<ComponentBackend<D>>,
    capabilities: Capabilities,
    /// HSM keystore directory used by `get_csr` to spin up a transient
    /// `SimHsm` for CSR signing. `None` means CSR is not supported.
    csr_keystore: Option<PathBuf>,
    /// Optional crypto provider for the HSM read/CSR ops (`get_csr`,
    /// `list_keys`, `get_device_id`). When `Some` (e.g. a link-B client), those
    /// ops route through it IN PREFERENCE to spinning up a transient `SimHsm`
    /// over `csr_keystore`; when `None` the keystore-backed path runs exactly as
    /// before. Set via [`Self::with_csr_crypto`].
    csr_crypto: Option<Arc<dyn hsm::HsmCryptoProvider>>,
}

impl<D: BlockDevice + Send + Sync + 'static> ComponentAdapter<D> {
    pub fn new(inner: Arc<ComponentBackend<D>>) -> Self {
        let capabilities = derive_capabilities(&inner);
        Self {
            inner,
            capabilities,
            csr_keystore: None,
            csr_crypto: None,
        }
    }

    /// Configure HSM CSR signing. Sets `Capabilities.hsm.supports_csr = true`
    /// and points `get_csr` at the keystore.
    pub fn with_csr_keystore(mut self, keystore: PathBuf) -> Self {
        self.csr_keystore = Some(keystore);
        // Reflect the new capability.
        if let Some(ref mut caps) = self.capabilities.hsm {
            caps.supports_csr = true;
        } else {
            self.capabilities.hsm = Some(HsmCaps {
                supports_csr: true,
                supports_key_install: false,
            });
        }
        self
    }

    /// Inject a crypto provider (e.g. a link-B-backed `LinkBClient` /
    /// `LinkBProvider`) used by `get_csr` / `list_keys` / `get_device_id` IN
    /// PREFERENCE to a transient `SimHsm` over `csr_keystore`. Also flips
    /// `Capabilities.hsm.supports_csr` (like [`Self::with_csr_keystore`]) so the
    /// capability stays honest even without a keystore. `None` (the default)
    /// keeps the keystore-backed path.
    pub fn with_csr_crypto(mut self, crypto: Arc<dyn hsm::HsmCryptoProvider>) -> Self {
        self.csr_crypto = Some(crypto);
        if let Some(ref mut caps) = self.capabilities.hsm {
            caps.supports_csr = true;
        } else {
            self.capabilities.hsm = Some(HsmCaps {
                supports_csr: true,
                supports_key_install: false,
            });
        }
        self
    }

    pub fn inner(&self) -> &Arc<ComponentBackend<D>> {
        &self.inner
    }
}

/// Map an HSM key type to the manifest-style label the `data/keys` SOVD
/// resource reports.
fn key_type_label(t: hsm::KeyType) -> &'static str {
    match t {
        hsm::KeyType::EcP256 => "EC-P256",
        hsm::KeyType::Aes256 => "AES-256",
        hsm::KeyType::Aes128 => "AES-128",
        hsm::KeyType::Ed25519 => "Ed25519",
        hsm::KeyType::HmacSha256 => "HMAC-SHA256",
    }
}

fn derive_capabilities<D: BlockDevice + Send + 'static>(b: &ComponentBackend<D>) -> Capabilities {
    let cfg = b.component_config();
    Capabilities {
        did_store: true,
        flash: Some(FlashCaps {
            dual_bank: !cfg.single_bank,
            supports_rollback: cfg.supports_rollback,
            supports_trial_boot: !cfg.single_bank,
            // Today's ComponentBackend has no public abort hook — wired in a follow-up.
            // Keep this honest with the actual implementation: false.
            abortable_after_finalize: false,
            // Phase 1 of Issue 2: surface the activator's declared reset kind
            // so the orchestrator can coalesce per-component restarts into a
            // single ECU-level `PUT status/restart` when needed. RT and host-os
            // activators override to `RequiresEcuReset`; everything else gets
            // the default `Local`. See tasks/reset-kind-and-status-restart.md.
            reset_kind: b.reset_kind(),
        }),
        lifecycle: Some(LifecycleCaps {
            restartable: true,
            has_runtime_state: b.has_vm_service(),
        }),
        hsm: b.has_hsm_provider().then_some(HsmCaps {
            supports_csr: true,
            supports_key_install: true,
        }),
        dtcs: true,
        clear_dtcs: true,
    }
}

#[async_trait]
impl<D: BlockDevice + Send + Sync + 'static> Component for ComponentAdapter<D> {
    fn id(&self) -> &str {
        &self.inner.entity_info().id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    async fn start(&self) -> MachineResult<()> {
        // No-op: the HSM daemon's lifecycle is owned externally now (the host
        // spawns the link-B backend; vhsm-ssd is a separate process), so a
        // component no longer starts an in-process HSM service here. Idempotent.
        Ok(())
    }

    async fn list_dids(&self, _filter: &DidFilter) -> MachineResult<Vec<DidEntry>> {
        let has_health = self.inner.has_vm_service();
        let mut entries: Vec<DidEntry> = DID_REGISTRY
            .iter()
            .filter(|d| {
                has_health || (d.did != did::DID_GUEST_STATE && d.did != did::DID_HEARTBEAT_SEQ)
            })
            .map(|d| DidEntry {
                key: d.did,
                kind: DidKind::Runtime, // cascade resolution; kind is informational
                id: d.id.to_string(),
                name: d.name.to_string(),
                writable: d.writable,
            })
            .collect();

        // Append runtime DIDs from NV that aren't in the static registry.
        let nv = self
            .inner
            .nv_lock()
            .map_err(|_| MachineError::Internal("nv lock poisoned".into()))?;
        let active = self
            .inner
            .running_bank()
            .map_err(|_| MachineError::Internal("running_bank lock poisoned".into()))?;
        if let Some(runtime) = nv.read_runtime(self.inner.bank_set(), active) {
            for i in 0..runtime.did_count as usize {
                let key = runtime.dids[i].did;
                if DID_REGISTRY.iter().any(|d| d.did == key) {
                    continue;
                }
                entries.push(DidEntry {
                    key,
                    kind: DidKind::Runtime,
                    id: format!("runtime_{key:04X}"),
                    name: format!("Runtime DID 0x{key:04X}"),
                    writable: true,
                });
            }
        }

        Ok(entries)
    }

    async fn read_did(&self, key: u16, _kind: DidKind) -> MachineResult<Bytes> {
        let nv = self
            .inner
            .nv_lock()
            .map_err(|_| MachineError::Internal("nv lock poisoned".into()))?;
        let running_bank = self
            .inner
            .running_bank()
            .map_err(|_| MachineError::Internal("running_bank lock poisoned".into()))?;
        match did::read_did(&*nv, self.inner.bank_set(), key, Some(running_bank)) {
            did::DidValue::Bytes(b) => Ok(Bytes::from(b)),
            did::DidValue::NotFound => Err(MachineError::NotFound(format!("DID 0x{key:04X}"))),
        }
    }

    async fn write_did(&self, key: u16, kind: DidKind, value: &[u8]) -> MachineResult<()> {
        if kind == DidKind::Factory {
            return Err(MachineError::PolicyRejected(
                "factory DIDs are read-only after provisioning".into(),
            ));
        }
        let mut nv = self
            .inner
            .nv_lock_mut()
            .map_err(|_| MachineError::Internal("nv lock poisoned".into()))?;
        match did::write_did(&mut *nv, self.inner.bank_set(), key, value) {
            Ok(true) => Ok(()),
            Ok(false) => Err(MachineError::Storage("runtime DID store full".into())),
            Err(e) => Err(MachineError::Storage(e.to_string())),
        }
    }

    async fn activation_state(&self) -> MachineResult<Option<ActivationState>> {
        let st = DiagnosticBackend::get_activation_state(&*self.inner)
            .await
            .map_err(map_backend_error)?;
        Ok(Some(st))
    }

    // ---------------------------------------------------------------
    // Install pipeline — delegates to ComponentBackend's existing flash methods
    // ---------------------------------------------------------------

    async fn start_install(&self) -> MachineResult<FlashSession> {
        let transfer_id = DiagnosticBackend::start_flash(&*self.inner)
            .await
            .map_err(map_backend_error)?;
        Ok(FlashSession {
            id: FlashId::new(transfer_id),
            target_bank: None, // ComponentBackend computes target from running_bank internally.
            max_chunk_size: 0,
        })
    }

    async fn authorize_install(&self) -> MachineResult<()> {
        self.inner
            .ensure_flash_can_start()
            .map_err(map_backend_error)
    }

    async fn upload_envelope(
        &self,
        _id: &FlashId,
        stream: EnvelopeStream,
    ) -> MachineResult<String> {
        // EnvelopeStream and sovd-core's PackageStream are the same underlying
        // type (Pin<Box<dyn Stream<Item = Result<Bytes, Box<dyn Error>>> + Send>>).
        // No conversion needed. ComponentBackend's receive_package_stream owns the
        // session lifecycle (AwaitingManifest → AwaitingPayload → Complete);
        // this method just feeds the next piece into it. We return the
        // package_id ComponentBackend issues, which the SOVD wire surfaces.
        DiagnosticBackend::receive_package_stream(&*self.inner, stream, None)
            .await
            .map_err(map_backend_error)
    }

    async fn finalize_install(&self, _id: &FlashId) -> MachineResult<()> {
        DiagnosticBackend::finalize_flash(&*self.inner)
            .await
            .map_err(map_backend_error)
    }

    async fn commit_install(&self, _id: &FlashId) -> MachineResult<()> {
        DiagnosticBackend::commit_flash(&*self.inner)
            .await
            .map_err(map_backend_error)
    }

    async fn rollback_install(&self, _id: &FlashId) -> MachineResult<()> {
        DiagnosticBackend::rollback_flash(&*self.inner)
            .await
            .map_err(map_backend_error)
    }

    async fn abort_install(&self, _id: &FlashId) -> MachineResult<()> {
        // Pre-finalize abort is always allowed: discard the staging session.
        // Post-finalize abort needs the bank pointer to flip back, which
        // ComponentBackend can't do today — reject with PolicyRejected so the
        // orchestrator sees a meaningful error rather than a silent no-op.
        if self.inner.flash_is_finalized() {
            return Err(MachineError::PolicyRejected(
                "cannot abort: install already finalized".into(),
            ));
        }
        self.inner.clear_flash_session();
        Ok(())
    }

    async fn install_status(&self, id: &FlashId) -> MachineResult<FlashStatus> {
        DiagnosticBackend::get_flash_status(&*self.inner, id.as_str())
            .await
            .map_err(map_backend_error)
    }

    async fn read_dtcs(&self, _filter: &DtcFilter) -> MachineResult<Vec<Fault>> {
        let res = DiagnosticBackend::get_faults(&*self.inner, None)
            .await
            .map_err(map_backend_error)?;
        Ok(res.faults)
    }

    async fn clear_dtcs(&self, group: Option<u32>) -> MachineResult<ClearFaultsResult> {
        DiagnosticBackend::clear_faults(&*self.inner, group)
            .await
            .map_err(map_backend_error)
    }

    async fn restart(&self) -> MachineResult<()> {
        DiagnosticBackend::ecu_reset(&*self.inner, 0)
            .await
            .map(|_| ())
            .map_err(map_backend_error)
    }

    async fn runtime_state(&self) -> MachineResult<RuntimeState> {
        // PR 2: stub. PR 3 will wire vm-service health query and parse it.
        Ok(RuntimeState {
            status: RuntimeStatus::Unknown,
            detail: serde_json::Value::Null,
        })
    }

    // ---------------------------------------------------------------
    // HSM
    // ---------------------------------------------------------------

    async fn get_csr(&self, key_id: &str) -> MachineResult<Csr> {
        use hsm::HsmCryptoProvider;

        // No provisioning-state gate: a device may re-provision with fresh certs
        // whenever it wants, and identity keys generated DURING provisioning
        // (e.g. tls-identity) can only be CSR'd afterwards. The key must exist —
        // generate_csr fails with KeyNotFound otherwise. The CSR subject CN is
        // the key_id (self-describing); the issuing CA sets the real cert subject
        // to the device id regardless.
        let handle = hsm::vhsm_proto::handle_for_key_id(key_id)
            .map(hsm::KeyHandle)
            .ok_or_else(|| {
                MachineError::Internal(format!("CSR for unknown key slot '{key_id}'"))
            })?;

        // Prefer the injected crypto provider (e.g. link-B); else spin up a
        // transient SimHsm over the on-disk keystore (the authoritative state
        // for that fallback path).
        let der = if let Some(ref crypto) = self.csr_crypto {
            crypto.generate_csr(handle, key_id)
        } else {
            let keystore = self
                .csr_keystore
                .as_ref()
                .ok_or(MachineError::NotSupported(
                    "get_csr (no keystore configured)",
                ))?;
            let tmp = hsm_sim_backend::SimHsm::new(keystore.clone());
            tmp.generate_csr(handle, key_id)
        }
        .map_err(|e| MachineError::Internal(format!("csr generation failed: {e}")))?;
        Ok(Csr::from_bytes(der))
    }

    async fn list_keys(&self) -> MachineResult<KeyInventory> {
        use hsm::{HsmCryptoProvider, HsmProvider};

        // The device reports its own provisioning state — no inference.
        let provisioned = matches!(
            self.inner.hsm_provisioning_state(),
            Some(Ok(hsm::ProvisioningState::Provisioned))
        );

        // Shared SlotInfo → public-only KeyDescriptor mapping. EVERY slot is
        // mapped through — key slots AND the monotonic-counter slot (the
        // time-floor). The counter is deliberately surfaced (it is safe to
        // expose: structure, not the counter value); it is NOT filtered out.
        // `public_key` is the already-resolved SPKI for asymmetric key slots
        // (safe to return), never any private bytes; the counter has none.
        let to_descriptor = |s: hsm::SlotInfo, public_key: Option<Vec<u8>>| KeyDescriptor {
            key_id: s.key_id,
            kind: match s.kind {
                hsm::SlotKind::Key(kt) => SlotKind::Key(key_type_label(kt).to_string()),
                hsm::SlotKind::Monotonic => SlotKind::Monotonic,
            },
            has_certificate: s.has_certificate,
            allowed_ops: s.allowed_ops,
            public_key,
        };
        // Asymmetric KEY slots have a public half worth returning; symmetric keys
        // and the monotonic counter do not.
        let wants_pubkey = |kind: &hsm::SlotKind| {
            matches!(
                kind,
                hsm::SlotKind::Key(hsm::KeyType::EcP256 | hsm::KeyType::Ed25519)
            )
        };

        // Prefer the injected crypto provider. HsmCryptoProvider has no
        // list_slots, so enumerate the well-known sumo-core slot registry
        // (which includes the time-floor counter) and keep the slots the backend
        // actually has (get_slot_info → KeyNotFound for absent ones). Else fall
        // back to the transient SimHsm, which lists the on-disk keystore's slots
        // plus the counter directly.
        let keys: Vec<KeyDescriptor> = if let Some(ref crypto) = self.csr_crypto {
            hsm::vhsm_proto::SUMO_CORE_SLOTS
                .iter()
                .filter_map(|slot| {
                    let handle = hsm::KeyHandle(slot.handle);
                    let info = crypto.get_slot_info(handle).ok()?;
                    let public_key = wants_pubkey(&info.kind)
                        .then(|| crypto.get_public_key_der(handle).ok())
                        .flatten();
                    Some(to_descriptor(info, public_key))
                })
                .collect()
        } else {
            let keystore = self
                .csr_keystore
                .as_ref()
                .ok_or(MachineError::NotSupported(
                    "list_keys (no keystore configured)",
                ))?;
            let tmp = hsm_sim_backend::SimHsm::new(keystore.clone());
            tmp.list_slots()
                .map_err(|e| MachineError::Internal(format!("list slots failed: {e}")))?
                .into_iter()
                .map(|k| {
                    let public_key = wants_pubkey(&k.kind)
                        .then(|| tmp.get_public_key_der(k.handle).ok())
                        .flatten();
                    to_descriptor(k, public_key)
                })
                .collect()
        };
        Ok(KeyInventory { provisioned, keys })
    }

    /// The ECU's self-sovereign id: a thumbprint of its HSM device key (the
    /// token `aud`). Read-only identity, served whether or not the device is
    /// provisioned — the device key exists from first boot, so no CSR-style gate.
    async fn get_device_id(&self) -> MachineResult<Option<String>> {
        use hsm::HsmCryptoProvider;
        let handle = hsm::KeyRole::DeviceDecryption.handle();

        // Prefer the injected crypto provider; else a transient SimHsm over the
        // keystore. With neither configured there's no device key to read.
        let der = if let Some(ref crypto) = self.csr_crypto {
            crypto.get_public_key_der(handle)
        } else {
            let Some(keystore) = self.csr_keystore.as_ref() else {
                return Ok(None);
            };
            let tmp = hsm_sim_backend::SimHsm::new(keystore.clone());
            tmp.get_public_key_der(handle)
        };
        match der {
            Ok(der) => Ok(Some(crate::sovd::identity::ecu_id_from_spki_der(&der))),
            Err(_) => Ok(None),
        }
    }

    // install_keys / list_dids / abort_install use trait defaults (NotSupported).
    // HSM key install today goes through the standard SOVD package flow
    // (receive_package -> upload_envelope), so install_keys is reserved for
    // future direct-install use cases.
}

fn map_backend_error(e: BackendError) -> MachineError {
    match e {
        BackendError::EntityNotFound(s)
        | BackendError::ParameterNotFound(s)
        | BackendError::OperationNotFound(s)
        | BackendError::OutputNotFound(s) => MachineError::NotFound(s),
        BackendError::SecurityRequired(level) => {
            MachineError::PolicyRejected(format!("security level {level} required"))
        }
        BackendError::SessionRequired(s) => {
            MachineError::PolicyRejected(format!("session change required: {s}"))
        }
        BackendError::NotSupported(_) => MachineError::NotSupported("backend operation"),
        BackendError::InvalidRequest(s) => MachineError::InvalidArgument(s),
        BackendError::Busy(s) => MachineError::Busy(s),
        BackendError::Timeout => MachineError::Internal("timeout".into()),
        BackendError::Protocol(s)
        | BackendError::Transport(s)
        | BackendError::Internal(s)
        | BackendError::RateLimited(s) => MachineError::Internal(s),
        BackendError::EcuError { message, nrc, sid } => MachineError::Internal(format!(
            "ECU error NRC=0x{nrc:02X} SID=0x{sid:02X}: {message}"
        )),
        BackendError::UpdateInProgress(s) => MachineError::Busy(s),
        BackendError::UnsupportedMediaType(s) => MachineError::WrongTarget(s),
    }
}
