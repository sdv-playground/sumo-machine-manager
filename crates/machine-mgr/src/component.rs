use async_trait::async_trait;
use bytes::Bytes;

use crate::error::{MachineError, MachineResult};
use crate::types::{
    Capabilities, Csr, DidFilter, DidKind, DtcFilter, EnvelopeStream, FlashId, FlashSession,
    InstallSource, KeyInventory, RuntimeState,
};
use crate::{ActivationState, ClearFaultsResult, Fault, FlashStatus};
use nv_store::types::BankSet;

/// One independently-updatable thing on the machine: the host OS, a guest VM,
/// the HSM, an attached ECU.
///
/// Required: `id`, `capabilities`. Everything else has a `NotSupported`
/// default — concrete components only implement the operations they support
/// and the `Capabilities` they return must be consistent with that.
#[async_trait]
pub trait Component: Send + Sync {
    /// Stable identifier (matches the `/components/{id}` path in SOVD).
    fn id(&self) -> &str;

    /// Capability descriptor. Controls which operations the orchestrator may
    /// attempt and (loosely) which trait methods it should expect to succeed.
    fn capabilities(&self) -> &Capabilities;

    /// The NV bank set this component's banked state lives in, if any. The node
    /// update-transaction gate maps the reboot-owed bitmask to/from component ids
    /// through this — `None` for components with no banked NV state (the gate's
    /// boolean phase still holds; it just can't name them). See
    /// [`node_update`](crate::node_update).
    fn bank_set(&self) -> Option<BankSet> {
        None
    }

    // ------------------------------------------------------------------
    // DID store
    // ------------------------------------------------------------------

    /// List the DIDs this component exposes (factory and runtime).
    async fn list_dids(&self, _filter: &DidFilter) -> MachineResult<Vec<DidEntry>> {
        Err(MachineError::NotSupported("list_dids"))
    }

    async fn read_did(&self, _key: u16, _kind: DidKind) -> MachineResult<Bytes> {
        Err(MachineError::NotSupported("read_did"))
    }

    async fn write_did(&self, _key: u16, _kind: DidKind, _value: &[u8]) -> MachineResult<()> {
        Err(MachineError::NotSupported("write_did"))
    }

    // ------------------------------------------------------------------
    // Install pipeline
    //
    // Lifecycle:
    //   start_install   → opens a session
    //   upload_envelope → streams a SUIT envelope to staging on disk;
    //                     verified inline; NOT yet applied
    //   finalize_install → APPLIES the staged image:
    //                       dual-bank: flips next-boot pointer (reboot needed)
    //                       single-bank (HSM): writes to live store immediately
    //   commit_install  → post-reboot/post-finalize: raise security version
    //                     floor, mark permanent
    //   rollback_install → dual-bank only: revert to previous bank
    //   abort_install   → discard session; pre-finalize always works,
    //                     post-finalize gated by FlashCaps.abortable_after_finalize
    // ------------------------------------------------------------------

    /// Provide a session-scoped pull source BEFORE `start_install`, for
    /// installs whose manifest references payloads by content-addressed URI
    /// (`upload_envelope`'s "fetch them transparently" contract). Components
    /// that can dereference content-addresses at finalize implement this; the
    /// default rejects, meaning the component installs integrated payloads
    /// only. The source is cleared when the session ends (finalize/abort).
    async fn set_install_source(&self, _source: InstallSource) -> MachineResult<()> {
        Err(MachineError::NotSupported("set_install_source"))
    }

    /// Open a new install session for this component. Returns the handle the
    /// caller uses for the rest of the pipeline.
    async fn start_install(&self) -> MachineResult<FlashSession> {
        Err(MachineError::NotSupported("start_install"))
    }

    async fn authorize_install(&self) -> MachineResult<()> {
        Ok(())
    }

    /// Stream a SUIT envelope into staging. Validates signature + security
    /// version + command sequence inline. Decrypts and decompresses payloads
    /// as they stream. Does NOT apply the install — staging only.
    ///
    /// Multi-file SOVD uploads (manifest, then per-payload) all hit this
    /// method; the impl owns session continuity. The `id` is informational —
    /// today's `ComponentAdapter` ignores it because `ComponentBackend` tracks one
    /// in-flight session per component.
    ///
    /// Returns a per-upload identifier (e.g. SOVD package_id). Callers may
    /// surface it on the wire or discard it.
    ///
    /// If the envelope references payloads by URI (rather than carrying them
    /// integrated), the implementation is expected to fetch them transparently.
    async fn upload_envelope(
        &self,
        _id: &FlashId,
        _stream: EnvelopeStream,
    ) -> MachineResult<String> {
        Err(MachineError::NotSupported("upload_envelope"))
    }

    /// Apply the staged install. Dual-bank: flips next-boot pointer (reboot
    /// required for new code to run). Single-bank (HSM): writes to live store
    /// immediately. After this point, `abort_install` is rejected unless
    /// `FlashCaps.abortable_after_finalize` is true.
    async fn finalize_install(&self, _id: &FlashId) -> MachineResult<()> {
        Err(MachineError::NotSupported("finalize_install"))
    }

    /// Post-reboot (or post-finalize for single-bank): raise the security
    /// version floor and mark this install permanent. The orchestrator calls
    /// this after verifying the new code is healthy.
    async fn commit_install(&self, _id: &FlashId) -> MachineResult<()> {
        Err(MachineError::NotSupported("commit_install"))
    }

    /// Dual-bank only: revert to the previously-active bank. Requires another
    /// reboot to take effect.
    async fn rollback_install(&self, _id: &FlashId) -> MachineResult<()> {
        Err(MachineError::NotSupported("rollback_install"))
    }

    /// Discard the install session. Always works pre-finalize. Post-finalize
    /// only works if `FlashCaps.abortable_after_finalize` is true.
    async fn abort_install(&self, _id: &FlashId) -> MachineResult<()> {
        Err(MachineError::NotSupported("abort_install"))
    }

    async fn install_status(&self, _id: &FlashId) -> MachineResult<FlashStatus> {
        Err(MachineError::NotSupported("install_status"))
    }

    /// State of bank activation (which bank is active, supports rollback,
    /// versions). `None` means the component has no concept of activation.
    async fn activation_state(&self) -> MachineResult<Option<ActivationState>> {
        Ok(None)
    }

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    /// Boot-time bring-up. Called once by the host after the registry is
    /// built. Implementations must be idempotent (the host may also call
    /// this after live reconfiguration). Default is a no-op.
    ///
    /// For HSM components: spawn the underlying HSM service so guests can
    /// reach it. The service must come up even before provisioning — guests
    /// need the listener to exist; key ops fail naturally on an empty
    /// keystore until provisioning completes.
    /// For VMs: no-op today (vm-service handles VM auto-start separately).
    /// For HSE / always-on hardware backends: no-op.
    async fn start(&self) -> MachineResult<()> {
        Ok(())
    }

    /// Restart the component. For the host this means reboot; for a guest VM
    /// it means stop+start through the VM lifecycle service; for HSM it may
    /// be a no-op or a daemon restart.
    async fn restart(&self) -> MachineResult<()> {
        Err(MachineError::NotSupported("restart"))
    }

    async fn runtime_state(&self) -> MachineResult<RuntimeState> {
        Err(MachineError::NotSupported("runtime_state"))
    }

    // ------------------------------------------------------------------
    // HSM-specific
    // ------------------------------------------------------------------

    /// Generate a PKCS#10 CSR for the named key slot (e.g. `tls-identity`,
    /// `device-decrypt`). The key must already exist in the keystore — identity
    /// keys generated during provisioning (like `tls-identity`) are CSR'd
    /// afterwards. No provisioning-state gate: a device may re-provision with
    /// fresh certs at any time.
    async fn get_csr(&self, _key_id: &str) -> MachineResult<Csr> {
        Err(MachineError::NotSupported("get_csr"))
    }

    /// The HSM component's key inventory — the `data/keys` SOVD resource: the
    /// device's provisioning state + its key slots (public metadata only).
    /// Default: not an HSM component.
    async fn list_keys(&self) -> MachineResult<KeyInventory> {
        Err(MachineError::NotSupported("list_keys"))
    }

    /// The ECU's self-sovereign id — a thumbprint of its HSM device key, used as
    /// the token `aud`. `None` for non-HSM components or before the device key
    /// exists. See `component_mgr::sovd::identity`.
    async fn get_device_id(&self) -> MachineResult<Option<String>> {
        Ok(None)
    }

    async fn install_keys(&self, _envelope: &[u8]) -> MachineResult<()> {
        Err(MachineError::NotSupported("install_keys"))
    }

    // ------------------------------------------------------------------
    // Faults / DTCs
    // ------------------------------------------------------------------

    async fn read_dtcs(&self, _filter: &DtcFilter) -> MachineResult<Vec<Fault>> {
        Err(MachineError::NotSupported("read_dtcs"))
    }

    async fn clear_dtcs(&self, _group: Option<u32>) -> MachineResult<ClearFaultsResult> {
        Err(MachineError::NotSupported("clear_dtcs"))
    }
}

/// Metadata for a single DID exposed by a component. Returned by `list_dids`.
#[derive(Debug, Clone)]
pub struct DidEntry {
    pub key: u16,
    pub kind: DidKind,
    /// Stable string identifier used by wire protocols as a path segment
    /// (e.g. `"serial_number"` or `"runtime_F40C"`).
    pub id: String,
    /// Human-readable display name, e.g. `"Serial Number"`.
    pub name: String,
    /// True if the DID is writable via `write_did`.
    pub writable: bool,
}
