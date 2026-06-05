//! VmBackend — DiagnosticBackend implementation for vm-mgr bank sets.
//!
//! Each instance manages one bank set (hypervisor, vm1, vm2, hsm) and provides:
//!
//! - Parameter read/write via NV DIDs
//! - Fault (DTC) management

#![allow(
    clippy::large_enum_variant,
    clippy::doc_lazy_continuation,
    clippy::match_like_matches_macro
)]
/// - SUIT-based firmware flash with A/B banking
/// - Session/security mode control
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::Utc;

use nv_store::block::BlockDevice;
use nv_store::store::NvStore;
use nv_store::types::*;

use sovd_core::backend::*;
use sovd_core::error::{BackendError, BackendResult};
use sovd_core::models::*;
use sovd_core::PackageStream;

use crate::did;
use crate::manifest_provider::{ManifestProvider, ManifestType, ValidatedFirmware};
use crate::ota;
use crate::sovd::security::SecurityProvider;

/// Vendor SOVD data-parameter id for the committed bank's signed IVD
/// manifest. `x-sumo-` prefix per ISO 17978-3 Table 70 vendor-extension
/// namespacing — the route is plain `/data/{id}` (SOVDd stays spec-pure /
/// format-agnostic); the vendor semantics live entirely here in vm-mgr.
pub const INSTALLED_MANIFEST_PARAM_ID: &str = "x-sumo-installed-manifest";

// ---------------------------------------------------------------------------
// Session / security state (per backend instance)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionState {
    Default,
    Programming,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecurityPhase {
    Locked,
    SeedAvailable,
    Unlocked,
}

#[derive(Debug, Clone)]
struct SecurityAccessState {
    phase: SecurityPhase,
    level: u8,
    pending_seed: Option<Vec<u8>>,
}

impl Default for SecurityAccessState {
    fn default() -> Self {
        Self {
            phase: SecurityPhase::Locked,
            level: 0,
            pending_seed: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Stored package (validated SUIT envelope)
// ---------------------------------------------------------------------------

struct StoredPackage {
    id: String,
    validated: ValidatedFirmware,
    status: PackageStatus,
}

/// A validated manifest (uploaded separately from payloads).
struct StoredManifest {
    raw_bytes: Vec<u8>,
}

/// A raw payload saved to disk (uploaded separately from manifest).
struct StoredPayload {
    path: std::path::PathBuf,
}

/// SUIT-derived facts for one uploaded manifest, cached so the
/// `GET /updates/{id}` detail body (ISO 17978-3 §7.18.3 Table 261) can be
/// enriched without re-reading / re-parsing the envelope at describe time.
///
/// Populated when the `"manifest"` bulk-data part arrives (the envelope is
/// already CBOR-decoded there for validation, so extraction is free), keyed
/// by the `file_id` the upload returned on the wire. The streaming pipeline
/// writes the *inner* payload straight to flash and drops the raw envelope
/// bytes, so a describe-time re-read isn't possible — caching at parse time
/// is the only honest source for these fields.
#[derive(Clone, Default)]
struct ManifestDescribeMeta {
    /// Human-readable name: SUIT model/vendor text + version, or the
    /// component path + version when no text name is present.
    update_name: Option<String>,
    /// SUIT text description (`suit-text-manifest-description`), if any.
    notes: Option<String>,
    /// Component identifiers named by the manifest, rendered as slash-joined
    /// segment paths (e.g. `vm1`, `rt/firmware`). One entry per SUIT component.
    component_paths: Vec<String>,
}

/// Extract the Table-261-relevant facts from an already-decoded SUIT manifest.
///
/// Pure / allocation-light; only reads the metadata the SUIT envelope
/// genuinely carries. `version_display` is the `ValidatedFirmware` version
/// string (text-version or the `seq-N` fallback) — used to qualify the name
/// when the manifest has a human model/vendor name.
fn extract_describe_meta(
    manifest: &sumo_onboard::manifest::Manifest,
    version_display: &str,
) -> ManifestDescribeMeta {
    // Prefer a human product/model name; fall back to the supplier/vendor
    // name. Qualify either with the version so the catalog entry is
    // self-describing (e.g. "Sumo VM1 1.2.0").
    let human_name = manifest
        .text_model_name(0)
        .or_else(|| manifest.text_vendor_name(0))
        .map(str::to_string);

    let version = manifest
        .text_version(0)
        .map(str::to_string)
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| version_display.to_string());

    // Render every component id the manifest names as a slash-joined
    // segment path (component ids are arrays of bstr segments).
    let component_paths: Vec<String> = (0..manifest.component_count())
        .filter_map(|i| manifest.component_id(i))
        .map(render_component_path)
        .filter(|p| !p.is_empty())
        .collect();

    let update_name = match human_name {
        Some(name) if !version.is_empty() => Some(format!("{name} {version}")),
        Some(name) => Some(name),
        // No SUIT text name: name from the first component path + version,
        // which is still strictly better than the bare register-time id.
        None => component_paths.first().map(|p| {
            if version.is_empty() {
                p.clone()
            } else {
                format!("{p} {version}")
            }
        }),
    };

    ManifestDescribeMeta {
        update_name,
        notes: manifest.text_description().map(str::to_string),
        component_paths,
    }
}

/// Render a SUIT component id (array of byte-string segments) as a
/// slash-joined UTF-8 path. Non-UTF-8 segments are hex-encoded so the
/// result is always printable. Empty input yields an empty string.
fn render_component_path(segments: &[Vec<u8>]) -> String {
    segments
        .iter()
        .map(|seg| match std::str::from_utf8(seg) {
            Ok(s) => s.to_string(),
            Err(_) => hex::encode(seg),
        })
        .collect::<Vec<_>>()
        .join("/")
}

// ---------------------------------------------------------------------------
// Flash session: sequential upload state machine
// ---------------------------------------------------------------------------

/// Tracks the sequential upload state within a flash session.
///
/// After start_flash(): AwaitingManifest
/// After manifest upload: AwaitingPayload(0)
/// After payload N: AwaitingPayload(N+1)
/// After all payloads: Complete
enum FlashSessionState {
    /// Waiting for manifest upload (first file in sequence).
    AwaitingManifest,
    /// Manifest received, waiting for payload at component index N.
    AwaitingPayload {
        manifest_bytes: Vec<u8>,
        #[allow(dead_code)] // TODO: use validated firmware metadata during payload processing
        validated: ValidatedFirmware,
        next_component: usize,
        total_components: usize,
    },
    /// All uploads received.
    Complete,
}

/// Where an uploaded file_id was placed, so `verify_part` can re-confirm
/// the part's integrity post-upload.
///
/// Two flavours:
///
/// * `Manifest` — the SUIT envelope as it arrived on the wire.  Small
///   (≤100 KB), kept whole in `packages[file_id]`.  We record the
///   upload-time outer SHA-256 so verify_part can compare directly
///   against what the SOVD wire recorded during `PUT /bulk-data`.
///
/// * `OnDisk` — a detached payload.  We can't keep the raw wire bytes
///   (multi-MB; the streaming pipeline writes the decrypted +
///   decompressed *inner* content straight to disk to avoid doubling
///   flash I/O).  So re-verification compares the file on disk against
///   the inner SHA-256 the streaming pipeline captured at write time
///   — which is itself the manifest's declared `image_digest`, already
///   verified against ciphertext during upload.  Catches on-disk
///   corruption between upload and finalize; doesn't and can't
///   re-verify the outer-on-the-wire hash post-stream.
enum UploadedPartLocation {
    Manifest {
        upload_sha256: [u8; 32],
    },
    OnDisk {
        path: PathBuf,
        inner_sha256: [u8; 32],
    },
}

// ---------------------------------------------------------------------------
// Flash transfer tracking
// ---------------------------------------------------------------------------

struct FlashTransferState {
    transfer_id: String,
    package_id: String,
    state: FlashState,
    image_size: u64,
    /// Guest `boot_id` captured just before reset. `Verifying → Activated`
    /// promotes once the live heartbeat reports a *different* boot_id —
    /// definitive proof of a new guest lifetime. We can't compare hb_seq
    /// here: qvm-shmem regions persist across stops/starts, so the new
    /// daemon's seq counter starts above the old one and a "seq dropped"
    /// check would never fire.
    ///
    /// `None` means the pre-reset health probe couldn't read a boot_id
    /// (vm-service down, factory-provisioning case, etc.). Then any new
    /// running heartbeat is accepted as a fresh boot.
    verify_baseline_boot_id: Option<u32>,
    /// `(relative_path, size, sha256)` for each payload as the streaming
    /// pipeline wrote it into the target bank dir. Lets
    /// `ivd_sign_staged_bank` build the IVD manifest without re-reading
    /// the bank from disk. Empty for the buffered (non-streaming) path
    /// and for pre-streaming-pipeline upload flows — `sign_bank` then
    /// falls back to a directory walk.
    streamed_files: Vec<hsm::ivd::IvdFile>,
}

// ---------------------------------------------------------------------------
// Component configuration
// ---------------------------------------------------------------------------

/// Per-component configuration for VmBackend behavior.
pub struct ComponentConfig {
    /// Whether this component supports rollback (false for HSM).
    pub supports_rollback: bool,
    /// Whether this component is single-banked (true for HSM — always bank A).
    pub single_bank: bool,
    /// SOVD entity_type for component identity.
    pub entity_type: String,
}

impl Default for ComponentConfig {
    fn default() -> Self {
        Self {
            supports_rollback: true,
            single_bank: false,
            entity_type: "vm".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// VmBackend
// ---------------------------------------------------------------------------

pub struct VmBackend<D: BlockDevice + Send + 'static> {
    entity_info: EntityInfo,
    capabilities: Capabilities,
    bank_set: BankSet,
    /// Per-slot behavioral data (on-disk dir, SUIT-URI → filename
    /// layout). Constructed by `BankSetSpec::for_well_known(bank_set)`
    /// in the existing constructors; Phase 3 lets component-factory
    /// supply a deployment-specific spec via `with_spec`.
    bank_spec: crate::bank_spec::BankSetSpec,
    config: ComponentConfig,
    nv: Arc<Mutex<NvStore<D>>>,
    manifest_provider: Arc<dyn ManifestProvider>,
    security_provider: Arc<dyn SecurityProvider>,
    packages: Mutex<HashMap<String, StoredPackage>>,
    manifests: Mutex<HashMap<String, StoredManifest>>,
    payloads: Mutex<HashMap<String, StoredPayload>>,
    /// Records every uploaded file_id's storage location for later
    /// per-part re-verification (SOVDd `/executions{verify}`). Manifest
    /// uploads point at the in-memory `packages` entry; detached
    /// payloads point at the on-disk bank-dir file.
    uploaded_parts: Mutex<HashMap<String, UploadedPartLocation>>,
    flash_session: Mutex<Option<FlashSessionState>>,
    flash_transfer: Mutex<Option<FlashTransferState>>,
    /// The bank the ECU is actually running on. Only changes on ecu_reset().
    /// NV active_bank may differ after install (it's the "next boot" bank).
    running_bank: Mutex<Bank>,
    session: Mutex<SessionState>,
    security: Mutex<SecurityAccessState>,
    next_id: Mutex<u64>,
    /// Optional TCP address ("host:port") for vm-service control API.
    /// When set, ecu_reset() POSTs to vm-service to restart the VM.
    /// Loopback only — same locality boundary as the prior Unix-socket
    /// path, but TCP avoids `tokio::net::UnixListener::accept()` not
    /// waking up reliably on QNX 7.1.
    vm_service_addr: Option<String>,
    /// Optional images directory — when set, firmware payloads are written
    /// to {images_dir}/{set}-{bank}.img during flash. Required for real
    /// image-based OTA (e.g. QEMU rootfs swap).
    images_dir: Option<PathBuf>,
    /// Tracks upload phase for activation state reporting.
    /// Set to Transferring during receive_package_stream so the campaign
    /// viewer can see that a firmware download is in progress.
    upload_phase: Mutex<Option<FlashState>>,
    /// Optional HSM provider — when set, HSM key material manifests
    /// (component_id `["hsm", "keys"]`) are routed to this provider
    /// instead of being written as a disk image.
    hsm_provider: Option<Arc<Mutex<dyn hsm::HsmProvider>>>,
    /// Optional bank activator — when set, ecu_reset() invokes activate()
    /// on the target bank directory instead of (or in addition to) symlink switching.
    bank_activator: Option<Arc<dyn machine_mgr::BankActivator>>,
    /// Synthetic health source — consulted by `read_data` for
    /// `guest_state` / `heartbeat_seq` when `vm_service_addr` is None.
    /// Set via `with_health_probe` (typically by supernova-mm for the
    /// RT component, wrapping `m7loader -q`). VMs leave this as None
    /// and use the vm-service HTTP path instead.
    health_probe: Option<Arc<dyn HealthProbe>>,
    /// In-memory cache of all NV-backed DID values. Populated at startup
    /// and updated atomically whenever NV is written (under the NV mutex
    /// + cache write lock). Reads bypass NV entirely — eliminates the
    /// 1-2 second per-call latency observed on QNX/eMMC during flash
    /// when the NV mutex is contended with write operations. RwLock so
    /// the campaign viewer's parallel-poll-of-many-DIDs runs concurrent.
    /// Keyed by raw 16-bit DID number.
    did_cache: std::sync::RwLock<std::collections::HashMap<u16, Vec<u8>>>,
    /// SUIT-derived Table-261 facts for uploaded manifests, keyed by the
    /// `file_id` the upload returned. Populated when the `"manifest"` part
    /// arrives; read by `describe_update_package` (via the diag adapter) to
    /// enrich `GET /updates/{id}`. Cleared with the rest of the flash
    /// session in `clear_flash_session` / `start_flash`.
    manifest_describe: Mutex<HashMap<String, ManifestDescribeMeta>>,
    /// Signature-verified IVD manifest of the RUNNING/committed bank,
    /// cached so the diagnostics reads that need it — the identity-DID
    /// overlay (`verified_bank_identity`) and the vendor
    /// `x-sumo-installed-manifest` data parameter — share a single verify
    /// pass rather than re-reading + re-verifying CBOR on every SOVD call.
    ///
    /// `(bank, manifest)`: the bank the cached manifest was read for, so a
    /// running-bank flip (ecu_reset) is detected and re-verified. `Arc` so
    /// readers clone cheaply without holding the lock across the JSON
    /// build. Invalidated to `None` on every NV write via
    /// `NvWriteGuard::drop` (same trigger as `did_cache`); the next reader
    /// re-populates lazily.
    verified_manifest_cache: Mutex<Option<(Bank, Arc<hsm::ivd::VerifiedManifest>)>>,
}

impl<D: BlockDevice + Send + 'static> VmBackend<D> {
    pub fn new(
        bank_set: BankSet,
        nv: Arc<Mutex<NvStore<D>>>,
        manifest_provider: Arc<dyn ManifestProvider>,
        security_provider: Arc<dyn SecurityProvider>,
        config: ComponentConfig,
    ) -> Self {
        Self::with_options(
            bank_set,
            nv,
            manifest_provider,
            security_provider,
            config,
            None,
            None,
        )
    }

    pub fn with_vm_service(
        bank_set: BankSet,
        nv: Arc<Mutex<NvStore<D>>>,
        manifest_provider: Arc<dyn ManifestProvider>,
        security_provider: Arc<dyn SecurityProvider>,
        config: ComponentConfig,
        vm_service_addr: Option<String>,
    ) -> Self {
        Self::with_options(
            bank_set,
            nv,
            manifest_provider,
            security_provider,
            config,
            vm_service_addr,
            None,
        )
    }

    pub fn with_options(
        bank_set: BankSet,
        nv: Arc<Mutex<NvStore<D>>>,
        manifest_provider: Arc<dyn ManifestProvider>,
        security_provider: Arc<dyn SecurityProvider>,
        config: ComponentConfig,
        vm_service_addr: Option<String>,
        images_dir: Option<PathBuf>,
    ) -> Self {
        let (id, name, desc) = match bank_set {
            BankSet::HostOs => ("host-os", "Host OS", "Host OS (IFS + rootfs) A/B bank set"),
            BankSet::Vm1 => ("vm1", "VM1", "Virtual machine slot 1"),
            BankSet::Vm2 => ("vm2", "VM2", "Virtual machine slot 2"),
            BankSet::Hsm => ("hsm", "HSM Key Store", "Hardware Security Module"),
            BankSet::App => ("app", "App", "Self-updating application component"),
            BankSet::Custom => ("custom", "Custom", "Deployment-specific bank slot"),
            // Phase 2 of the deep refactor will look these up from
            // deployment config; for now any slot beyond the 6
            // well-known ones gets a generic stub.
            _ => ("custom", "Custom", "Deployment-specific bank slot"),
        };

        // Read the current active bank at startup — this is what we're running on.
        let running_bank = if config.single_bank {
            Bank::A // single-banked components always run on bank A
        } else {
            let nv_guard = nv.lock().unwrap();
            nv_guard
                .read_boot_state()
                .map(|s| s.banks[bank_set.as_index()].active_bank)
                .unwrap_or(Bank::A)
        };

        let backend = Self {
            entity_info: EntityInfo {
                id: id.to_string(),
                name: name.to_string(),
                entity_type: config.entity_type.clone(),
                description: Some(desc.to_string()),
                href: format!("/vehicle/v1/components/{id}"),
                status: None,
            },
            capabilities: Capabilities {
                read_data: true,
                write_data: true,
                faults: true,
                clear_faults: true,
                software_update: true,
                io_control: false,
                sessions: true,
                security: true,
                sub_entities: false,
                subscriptions: false,
                logs: false,
                operations: false,
            },
            bank_set,
            bank_spec: crate::bank_spec::BankSetSpec::for_well_known(bank_set),
            config,
            nv,
            manifest_provider,
            security_provider,
            packages: Mutex::new(HashMap::new()),
            uploaded_parts: Mutex::new(HashMap::new()),
            manifests: Mutex::new(HashMap::new()),
            payloads: Mutex::new(HashMap::new()),
            flash_session: Mutex::new(None),
            flash_transfer: Mutex::new(None),
            running_bank: Mutex::new(running_bank),
            session: Mutex::new(SessionState::Default),
            security: Mutex::new(SecurityAccessState::default()),
            next_id: Mutex::new(1),
            vm_service_addr,
            images_dir,
            upload_phase: Mutex::new(None),
            hsm_provider: None,
            bank_activator: None,
            health_probe: None,
            did_cache: std::sync::RwLock::new(std::collections::HashMap::new()),
            manifest_describe: Mutex::new(HashMap::new()),
            verified_manifest_cache: Mutex::new(None),
        };
        // Populate DID cache from NV once at construction time. After this,
        // SOVD reads of NV-backed DIDs hit RAM only — see refresh_did_cache.
        {
            let nv_guard = backend.nv.lock().unwrap();
            backend.refresh_did_cache_locked(&*nv_guard);
        }
        backend
    }

    /// Override the component display name (shown in SOVD component listing).
    pub fn with_display_name(mut self, name: String) -> Self {
        self.entity_info.name = name;
        self
    }

    /// Override the bank-set spec (on-disk dir + URI→filename layout).
    /// Constructors default to `BankSetSpec::for_well_known(bank_set)`;
    /// component-factory uses this to inject deployment-config-driven
    /// values once Phase 3 wires the ComponentSpec → BankSetSpec path.
    pub fn with_bank_spec(mut self, spec: crate::bank_spec::BankSetSpec) -> Self {
        self.bank_spec = spec;
        self
    }

    /// Set an HSM provider for routing key material manifests.
    pub fn with_hsm_provider(mut self, provider: Arc<Mutex<dyn hsm::HsmProvider>>) -> Self {
        self.hsm_provider = Some(provider);
        self
    }

    /// Set a bank activator for post-install bank activation.
    pub fn with_bank_activator(mut self, activator: Arc<dyn machine_mgr::BankActivator>) -> Self {
        self.bank_activator = Some(activator);
        self
    }

    /// Set a synthetic health probe used by `read_data` for `guest_state`
    /// / `heartbeat_seq` when the component has no vm-service backing
    /// (activator-backed components like RT/M7). Wraps something like
    /// `m7loader -q` with internal caching to keep the SOVD hot path
    /// cheap. Returning `None` from the probe → `guest_state = "offline"`.
    pub fn with_health_probe(mut self, probe: Arc<dyn HealthProbe>) -> Self {
        self.health_probe = Some(probe);
        self
    }

    fn next_id(&self) -> String {
        let mut id = self.next_id.lock().unwrap();
        let v = *id;
        *id += 1;
        v.to_string()
    }

    /// Re-read every NV-backed DID and atomically replace the in-memory
    /// cache. Caller must already hold the NV mutex (passed as `nv`) so
    /// the NV-read side is consistent with concurrent writers.
    ///
    /// **Build-then-swap**: the new cache is built WITHOUT holding the
    /// cache lock, so concurrent readers keep hitting the old cache
    /// during the slow per-DID NV scan. Only the final HashMap swap is
    /// done under the cache write lock — that's a single pointer move
    /// in `mem::replace`, microseconds. This avoids the 2-second
    /// reader-block we had with `clear() + insert(...)` under lock.
    ///
    /// Health DIDs (guest_state, heartbeat_seq) are deliberately NOT
    /// cached — they go through `query_vm_health` which is already a
    /// fast in-memory loopback HTTP read against vm-service.
    ///
    /// Called from:
    /// - `with_options` (one-shot at startup)
    /// - automatic `NvWriteGuard::drop` after every NV write
    /// - factory_reset (full re-population)
    fn refresh_did_cache_locked(&self, nv: &NvStore<D>) {
        let rb = *self.running_bank.lock().unwrap();

        // Invalidate the verified-manifest cache in lock-step with the DID
        // cache. This is the single funnel for both startup and every NV
        // write (`NvWriteGuard::drop`), so dropping it here covers
        // install/commit/ecu_reset. The identity overlay below re-populates
        // it via `verified_bank_identity`; the vendor
        // `x-sumo-installed-manifest` reader re-populates lazily on demand.
        *self
            .verified_manifest_cache
            .lock()
            .expect("verified_manifest_cache poisoned") = None;

        // Build the new map outside any cache lock — readers proceed
        // against the old map throughout this loop.
        let mut new_cache: std::collections::HashMap<u16, Vec<u8>> =
            std::collections::HashMap::with_capacity(DID_REGISTRY.len());
        for entry in DID_REGISTRY.iter() {
            // Skip health DIDs — sourced from vm-service, not NV.
            if entry.did == did::DID_GUEST_STATE || entry.did == did::DID_HEARTBEAT_SEQ {
                continue;
            }
            if let did::DidValue::Bytes(bytes) =
                did::read_did(nv, self.bank_set, entry.did, Some(rb))
            {
                new_cache.insert(entry.did, bytes);
            }
        }

        // Overlay the SW-identity DIDs (F187-F19E) from the running
        // bank's signature-verified IVD manifest — the single source for
        // these now that they're out of NvFwMeta. `read_did` returns
        // NotFound for them above, so this is the only insert. Verifying
        // the signature here (once per NV write / boot, not per SOVD read)
        // keeps `read_data` on the cheap in-RAM path while still proving
        // the served identity is the one the device signed. Invalidation
        // is automatic: every install/commit/ecu_reset refreshes through
        // this function via `NvWriteGuard::drop`.
        for (did, bytes) in self.identity_did_bytes(rb) {
            new_cache.insert(did, bytes);
        }

        // Atomic swap — lock held for a single move, microseconds.
        *self.did_cache.write().expect("did_cache poisoned") = new_cache;
    }

    /// Acquire the NV mutex with a write-side guard that automatically
    /// refreshes the DID cache when the guard drops.
    ///
    /// **Use this for every NV write site.** Readers can keep using
    /// `self.nv.lock()` directly — they don't need the refresh. Writers
    /// MUST go through this so the cache stays in sync; forgetting to
    /// refresh on a callsite would silently leave stale DID values
    /// served via SOVD. Pushing the refresh into `Drop` makes it
    /// impossible to forget.
    ///
    /// The refresh runs while the NV mutex is still held, so a reader
    /// scheduled after the write sees the new cache atomically with
    /// the new NV state. After the refresh, the mutex drops in the
    /// normal way.
    fn nv_write(&self) -> BackendResult<NvWriteGuard<'_, D>> {
        let inner = self
            .nv
            .lock()
            .map_err(|_| BackendError::Internal("nv lock poisoned".into()))?;
        Ok(NvWriteGuard {
            backend: self,
            inner: Some(inner),
        })
    }

    // =================================================================
    // Accessors used by component_adapter::VmBackendComponent.
    // Kept narrow on purpose — the adapter is the only outside caller.
    // =================================================================

    pub fn entity_info(&self) -> &EntityInfo {
        &self.entity_info
    }

    /// SUIT-derived Table-261 facts cached for the manifest uploaded under
    /// `file_id`, if any. Returns `(update_name, notes, component_paths)`:
    ///
    /// * `update_name` — human name + version (or component-path + version).
    /// * `notes` — SUIT text description.
    /// * `component_paths` — slash-joined SUIT component-id segment paths.
    ///
    /// `None` when no manifest was cached for that `file_id` (e.g. the part
    /// was a detached payload, or the envelope failed to parse) — the
    /// describe path then keeps the format-agnostic default. Owned clones so
    /// the caller never holds the cache lock across `.await`.
    pub fn manifest_describe_facts(
        &self,
        file_id: &str,
    ) -> Option<(Option<String>, Option<String>, Vec<String>)> {
        let cache = self.manifest_describe.lock().ok()?;
        cache.get(file_id).map(|m| {
            (
                m.update_name.clone(),
                m.notes.clone(),
                m.component_paths.clone(),
            )
        })
    }

    pub fn component_config(&self) -> &ComponentConfig {
        &self.config
    }

    pub fn bank_set(&self) -> BankSet {
        self.bank_set
    }

    pub fn has_vm_service(&self) -> bool {
        self.vm_service_addr.is_some()
    }

    /// Reset kind declared by this component's bank activator, or
    /// [`ResetKind::Local`] when no activator is configured (e.g. VM
    /// components without a custom activator: qvm/process cycle is local).
    /// `derive_capabilities` reads this to populate `FlashCaps.reset_kind`.
    pub fn reset_kind(&self) -> machine_mgr::ResetKind {
        self.bank_activator
            .as_ref()
            .map(|a| a.reset_kind())
            .unwrap_or(machine_mgr::ResetKind::Local)
    }

    /// The bank an OTA upload should write to: the *inactive* bank for dual-bank
    /// components, or `Bank::A` for single-bank ones (HSM).
    ///
    /// For activator-backed components the `current` symlink under
    /// `images_dir/<dir_name>/` is the source of truth — it survives
    /// factory resets and doesn't depend on NV flip timing. Falls back
    /// to NV when no symlink exists (first-ever flash).
    fn determine_target_bank(&self) -> BackendResult<Bank> {
        if self.config.single_bank {
            return Ok(Bank::A);
        }
        if self.bank_activator.is_some() {
            if let Some(active) = self.read_current_symlink() {
                return Ok(active.other());
            }
        }
        let nv = self
            .nv
            .lock()
            .map_err(|_| BackendError::Internal("nv lock".into()))?;
        let state = nv
            .read_boot_state()
            .ok_or_else(|| BackendError::Internal("no boot state".into()))?;
        let idx = self.bank_set.as_index();
        Ok(state.banks[idx].active_bank.other())
    }

    /// Read the `current` symlink under `images_dir/<dir_name>/` and return
    /// the bank it points to, or `None` if missing / unreadable.
    fn read_current_symlink(&self) -> Option<Bank> {
        let images_dir = self.images_dir.as_ref()?;
        let symlink_path = images_dir.join(&self.bank_spec.dir_name).join("current");
        let target = std::fs::read_link(&symlink_path).ok()?;
        let name = target.file_name()?.to_str()?;
        match name {
            "bank_a" => Some(Bank::A),
            "bank_b" => Some(Bank::B),
            _ => None,
        }
    }

    /// Atomically flip the `current` symlink to point at `bank`.
    fn flip_current_symlink(&self, bank: Bank) {
        let Some(images_dir) = self.images_dir.as_ref() else {
            return;
        };
        let dir = images_dir.join(&self.bank_spec.dir_name);
        let symlink_path = dir.join("current");
        let target = Path::new(bank_dir_name(bank));
        let tmp_link = symlink_path.with_extension("tmp");
        let _ = std::fs::remove_file(&tmp_link);
        if let Err(e) = std::os::unix::fs::symlink(target, &tmp_link)
            .and_then(|()| std::fs::rename(&tmp_link, &symlink_path))
        {
            tracing::warn!(
                bank_set = ?self.bank_set,
                "failed to flip current symlink: {e}"
            );
        } else {
            tracing::info!(
                bank_set = ?self.bank_set,
                bank = ?bank,
                "flipped current -> {}",
                bank_dir_name(bank),
            );
        }
    }

    /// Path of the target bank directory under `images_dir`. `None` if no
    /// images_dir is configured (tests / in-memory only).
    fn target_bank_dir(&self, target: Bank) -> Option<PathBuf> {
        self.images_dir.as_ref().map(|images_dir| {
            images_dir
                .join(&self.bank_spec.dir_name)
                .join(bank_dir_name(target))
        })
    }

    /// Copy any files in the active bank that don't already exist in
    /// the target bank. This makes every OTA implicitly partial: a
    /// SUIT envelope that carried only some components ends with a
    /// complete target bank, with unstreamed files seeded from active.
    /// A full envelope that streamed every file is a no-op for this
    /// step (every file already exists in target).
    ///
    /// Must run AFTER all streaming finishes and BEFORE IVD signing,
    /// so the signature covers the final bank contents.
    ///
    /// No-op cases (returns Ok without doing anything):
    ///   - single-bank bank-sets (HSM) — no "other" bank to seed from
    ///   - no images_dir configured (in-memory test backends)
    ///   - active bank dir doesn't exist (factory first-flash)
    pub(crate) fn seed_target_from_active(&self, target: Bank) -> BackendResult<()> {
        if self.config.single_bank {
            // HSM-style single-bank — no peer to seed from.
            return Ok(());
        }

        let Some(images_dir) = self.images_dir.as_ref() else {
            // In-memory test backends — no on-disk bank to seed.
            return Ok(());
        };

        let nv = self
            .nv
            .lock()
            .map_err(|_| BackendError::Internal("nv lock".into()))?;
        let state = nv
            .read_boot_state()
            .ok_or_else(|| BackendError::Internal("no boot state".into()))?;
        let idx = self.bank_set.as_index();
        let active = state.banks[idx].active_bank;
        drop(nv);

        if active == target {
            // Defensive — `determine_target_bank` always returns the
            // .other() of active, but a future refactor that breaks
            // this invariant shouldn't silently corrupt the active
            // bank by self-seeding.
            return Ok(());
        }

        let set_name = &self.bank_spec.dir_name;
        let source_dir = images_dir.join(set_name).join(bank_dir_name(active));
        let target_dir = images_dir.join(set_name).join(bank_dir_name(target));

        match crate::bank_seed::seed_missing_files(&source_dir, &target_dir) {
            Ok(seeded) if seeded.is_empty() => {
                tracing::debug!(
                    target = %target_dir.display(),
                    source = %source_dir.display(),
                    "bank seed: no files copied (full update or empty active)"
                );
                Ok(())
            }
            Ok(seeded) => {
                tracing::info!(
                    target = %target_dir.display(),
                    source = %source_dir.display(),
                    count = seeded.len(),
                    paths = ?seeded,
                    "bank seed: copied unstreamed files from active bank"
                );
                Ok(())
            }
            Err(e) => {
                tracing::error!(
                    target = %target_dir.display(),
                    source = %source_dir.display(),
                    error = %e,
                    "bank seed failed — refusing to sign/activate a partial bank"
                );
                Err(BackendError::Internal(format!(
                    "bank seed from {} to {}: {e}",
                    source_dir.display(),
                    target_dir.display()
                )))
            }
        }
    }

    /// Self-sign the staged bank with the HSM's `ivd-signing` key so
    /// external secure boot can validate it before launch. Called at
    /// each `AwaitingActivation` transition — bank contents are
    /// final, but the bank pointer hasn't flipped yet, so the sig
    /// lives WITH the staged bank. Rollback wipes the bank and its
    /// sig together; trial flip just exposes the staged bank with
    /// its existing sig intact.
    ///
    /// Contract: signing is REQUIRED for every flash that produces a
    /// real bank dir with real payloads. Three skip paths and no
    /// others:
    ///
    /// 1. No `images_dir` (in-memory test) — backend has no place to
    ///    put files; tests assert via NV state.
    /// 2. Bank dir missing (pre-streaming code path) — caller hasn't
    ///    staged anything yet, nothing to sign.
    /// 3. Bank dir is payload-empty (HSM single-bank, where the
    ///    keystore lives at `keystore_path` not in the bank dir, and
    ///    attestation rides on the provisioning envelope chain).
    ///
    /// Pre-provisioning exception: if the HSM is reachable but
    /// `is_provisioned()` is false, the `ivd-signing` key doesn't
    /// exist yet — log a warning and skip. Banks produced in this
    /// state aren't boot-eligible once verified launch is wired in;
    /// the next flash post-provision will land sigs as expected.
    ///
    /// Any other condition (no HSM provider when payloads are
    /// present, signing failure, mutex poisoned) returns an error
    /// rather than silently shipping an unsigned bank.
    fn ivd_sign_staged_bank(&self, target: Bank) -> BackendResult<()> {
        // (1) Test-mode and legitimate no-op skips first — these are
        //     independent of HSM state.
        let Some(bank_dir) = self.target_bank_dir(target) else {
            tracing::debug!("ivd sign: no images_dir; skipping (in-memory test mode)");
            return Ok(());
        };
        if !bank_dir.exists() {
            tracing::debug!(
                bank_dir = %bank_dir.display(),
                "ivd sign: bank dir absent; skipping (pre-streaming path)",
            );
            return Ok(());
        }
        if bank_dir_is_payload_empty(&bank_dir) {
            tracing::debug!(
                bank_dir = %bank_dir.display(),
                "ivd sign: bank dir has no payload files; skipping (HSM bank / out-of-band attestation)",
            );
            return Ok(());
        }

        let bank_id = format!("{}/{}", &self.bank_spec.dir_name, bank_dir_name(target),);

        // (2) Past here we have a real bank with real payloads → HSM
        //     attachment is required. A missing provider means the
        //     wiring is broken (component-factory / sovd_main should
        //     have attached one); fail loud rather than ship unsigned.
        let hsm_arc = self.hsm_provider.as_ref().ok_or_else(|| {
            BackendError::Internal(format!(
                "ivd sign {bank_id}: no HSM provider attached — wiring bug"
            ))
        })?;
        let hsm = hsm_arc
            .lock()
            .map_err(|_| BackendError::Internal("ivd sign: hsm mutex poisoned".into()))?;

        // (3) Pre-provisioning exception: the HSM is reachable but the
        //     `ivd-signing` key doesn't exist yet. Skip with a warning;
        //     the bank is intentionally un-sealed until the next flash
        //     after HSM provisioning.
        match hsm.is_provisioned() {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(
                    bank_id = %bank_id,
                    "ivd sign: HSM not yet provisioned — skipping (bank is not boot-eligible until re-flashed post-provision)",
                );
                return Ok(());
            }
            Err(e) => {
                return Err(BackendError::Internal(format!(
                    "ivd sign {bank_id}: hsm provisioning probe failed: {e}"
                )));
            }
        }

        // Compute the install-time generation counter (gen) directly
        // from NV state. This must agree with what ota::install_inner
        // will write into target's NvFwMeta — they both derive it as
        // `committed_bank.gen + 1`. Two reasons it has to be computed
        // here independently (not read back from NvFwMeta):
        //
        // - In the multi-POST upload path this function runs at
        //   "all payloads received" but install_precomputed doesn't
        //   run until transferexit. NvFwMeta for the target hasn't
        //   been written yet.
        // - The OTA flow is serialized (start_flash rejects
        //   concurrent flashes via InTrial), so both call sites read
        //   the same NV state and arrive at the same gen.
        //
        // The committed bank is whichever of {active, active.other()}
        // currently has committed=true. If active is committed, that's
        // the committed bank. If we're already in trial mode (active=
        // target, committed=false), the OTHER bank is the
        // previously-committed one.
        let gen = {
            let nv = self
                .nv
                .lock()
                .map_err(|_| BackendError::Internal("ivd sign: nv mutex poisoned".into()))?;
            let state = nv.read_boot_state().ok_or_else(|| {
                BackendError::Internal(format!("ivd sign {bank_id}: NV boot state missing"))
            })?;
            let idx = self.bank_set.as_index();
            let committed_bank = if state.banks[idx].committed {
                state.banks[idx].active_bank
            } else {
                state.banks[idx].active_bank.other()
            };
            let committed_gen = nv
                .read_fw_meta(self.bank_set, committed_bank)
                .map(|m| m.gen)
                .unwrap_or(0);
            committed_gen + 1
        };

        // Reuse the per-file hashes captured by the streaming pipeline
        // when available — the OEM SUIT manifest already authenticated
        // each payload's digest at write time, so re-hashing the bank
        // from disk here is duplicate work (~2.5 s on the CVC's 80 MB
        // rootfs). Empty stash → fall back to walk + hash.
        let streamed_files = {
            let ft = self.flash_transfer.lock().map_err(|_| {
                BackendError::Internal("ivd sign: flash_transfer mutex poisoned".into())
            })?;
            ft.as_ref()
                .map(|t| t.streamed_files.clone())
                .unwrap_or_default()
        };

        // The firmware SW identity (SUIT-extracted at validate time) is
        // sealed into the signed manifest here — this is now the single
        // source for the F187-F19E identification DIDs. Resolved from the
        // package the current flash transfer points at.
        let identity = self.current_install_identity();

        let _manifest = if streamed_files.is_empty() {
            hsm::ivd::sign_bank(&*hsm, &bank_dir, gen, identity)
                .map_err(|e| BackendError::Internal(format!("ivd sign {bank_id}: {e}")))?
        } else {
            hsm::ivd::sign_bank_with_files(&*hsm, &bank_dir, gen, identity, streamed_files, None)
                .map_err(|e| BackendError::Internal(format!("ivd sign {bank_id}: {e}")))?
        };
        tracing::info!(
            bank_id = %bank_id,
            bank_dir = %bank_dir.display(),
            gen,
            "ivd sign OK",
        );
        Ok(())
    }

    /// The firmware SW identity to seal into the IVD manifest being
    /// signed: derived from the SUIT-extracted `ImageMeta` of the package
    /// the current flash transfer points at. Empty (all-default) when no
    /// package is in scope (e.g. a re-sign with no active transfer) — the
    /// manifest then carries a blank identity, which reads back as
    /// all-NUL DIDs, matching the prior zero-initialised behaviour.
    fn current_install_identity(&self) -> hsm::ivd::IvdIdentity {
        let package_id = {
            let ft = self.flash_transfer.lock().ok();
            ft.and_then(|g| g.as_ref().map(|t| t.package_id.clone()))
                .unwrap_or_default()
        };
        if package_id.is_empty() {
            return hsm::ivd::IvdIdentity::default();
        }
        let packages = match self.packages.lock() {
            Ok(p) => p,
            Err(_) => return hsm::ivd::IvdIdentity::default(),
        };
        packages
            .get(&package_id)
            .map(|p| p.validated.image_meta.to_ivd_identity())
            .unwrap_or_default()
    }

    /// Read + signature-verify a bank's IVD manifest and return the whole
    /// [`VerifiedManifest`] (decoded manifest + raw bytes + signature),
    /// caching it per-bank so repeated diagnostics reads share one verify
    /// pass. The cache is invalidated on every NV write (see
    /// `refresh_did_cache_locked`), so the served manifest always reflects
    /// the latest install/commit/ecu_reset.
    ///
    /// Returns `None` when the bank has no verifiable manifest (no
    /// images_dir, no HSM, not provisioned, no manifest yet, or a bad
    /// signature). A bad signature is logged at warn; absent/unsigned is
    /// debug (normal for factory-fresh / unprovisioned banks).
    ///
    /// Used for the RUNNING/committed bank: `read_data` of the identity
    /// DIDs and the vendor `x-sumo-installed-manifest` parameter both pass
    /// `*self.running_bank`, the same bank whose identity overlay is built
    /// in `refresh_did_cache_locked`.
    fn verified_bank_manifest(&self, bank: Bank) -> Option<Arc<hsm::ivd::VerifiedManifest>> {
        // Fast path: return the cached manifest if it's for this bank.
        {
            let cache = self
                .verified_manifest_cache
                .lock()
                .expect("verified_manifest_cache poisoned");
            if let Some((cached_bank, vm)) = cache.as_ref() {
                if *cached_bank == bank {
                    return Some(Arc::clone(vm));
                }
            }
        }

        // Slow path: read + verify, then memoise for this bank.
        let bank_dir = self.target_bank_dir(bank)?;
        let hsm_arc = self.hsm_provider.as_ref()?;
        let hsm = hsm_arc.lock().ok()?;
        match hsm::ivd::read_manifest(&*hsm, &bank_dir) {
            Ok(vm) => {
                let vm = Arc::new(vm);
                *self
                    .verified_manifest_cache
                    .lock()
                    .expect("verified_manifest_cache poisoned") = Some((bank, Arc::clone(&vm)));
                Some(vm)
            }
            Err(hsm::ivd::IvdError::SignatureInvalid) => {
                tracing::warn!(
                    bank_set = ?self.bank_set,
                    bank = ?bank,
                    "identity: IVD manifest signature INVALID; refusing to serve it",
                );
                None
            }
            Err(e) => {
                tracing::debug!(
                    bank_set = ?self.bank_set,
                    bank = ?bank,
                    error = %e,
                    "identity: no verifiable IVD manifest; identity DIDs unavailable",
                );
                None
            }
        }
    }

    /// Read + signature-verify a bank's IVD manifest and return the
    /// firmware [`IvdIdentity`] it carries — the single source for the
    /// SW-identity DIDs (F187-F19E) and version labels now that they're
    /// out of NvFwMeta. Thin projection over [`Self::verified_bank_manifest`].
    fn verified_bank_identity(&self, bank: Bank) -> Option<hsm::ivd::IvdIdentity> {
        self.verified_bank_manifest(bank)
            .map(|vm| vm.manifest.identity.clone())
    }

    /// The `(did, bytes)` pairs for the 9 SW-identity DIDs of `bank`,
    /// each converted to its historical fixed-width UDS byte form. Empty
    /// when the bank has no verifiable identity (see
    /// [`Self::verified_bank_identity`]).
    fn identity_did_bytes(&self, bank: Bank) -> Vec<(u16, Vec<u8>)> {
        match self.verified_bank_identity(bank) {
            Some(id) => identity_to_did_bytes(&id),
            None => Vec::new(),
        }
    }

    /// Wipe the target bank dir (frees ~1 image worth of space) and remove any
    /// orphaned staged files left in `images_dir` root by previous flashes.
    /// Called at flash-session start so the incoming payload lands in a clean,
    /// space-reclaimed location on the same filesystem as its final home.
    fn prepare_target_bank_dir(&self, target: Bank) -> BackendResult<()> {
        let Some(images_dir) = self.images_dir.as_ref() else {
            return Ok(());
        };
        let set_name = &self.bank_spec.dir_name;
        let bank_dir = images_dir.join(set_name).join(bank_dir_name(target));
        std::fs::create_dir_all(&bank_dir).map_err(|e| {
            BackendError::Internal(format!("create bank dir {}: {e}", bank_dir.display()))
        })?;
        let mut cleared = 0usize;
        if let Ok(entries) = std::fs::read_dir(&bank_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Err(e) = std::fs::remove_file(&path) {
                        tracing::warn!("failed to clear {}: {e}", path.display());
                    } else {
                        cleared += 1;
                    }
                }
            }
        }
        tracing::info!(
            target = %bank_dir.display(),
            cleared,
            "prepared target bank dir for {set_name}"
        );

        // Wipe legacy staged files in images_dir root (pre-refactor layout).
        // Free standing here so an upgrade path doesn't leave them squatting
        // on space the new upload needs.
        for suffix in &[
            "staged.img",
            "kernel-staged.img",
            "config-staged.yaml",
            "qvm-config-staged.conf",
        ] {
            let p = images_dir.join(format!("{set_name}-{suffix}"));
            if p.exists() {
                let _ = std::fs::remove_file(&p);
            }
        }
        // And any pre-refactor compressed-input scratch tmps. The component
        // index is bounded by the SUIT envelope's payload count (currently
        // <= 4 for VMs); 16 covers any reasonable manifest.
        for n in 0..16 {
            let p = images_dir.join(format!("{set_name}-upload-{n}.tmp"));
            if p.exists() {
                let _ = std::fs::remove_file(&p);
            }
        }
        Ok(())
    }

    pub fn has_hsm_provider(&self) -> bool {
        self.hsm_provider.is_some()
    }

    /// Bring up the HSM service (if this backend wraps one). No-op when
    /// no provider is attached or when the backend's HsmProvider impl
    /// reports the service was already running. Errors are surfaced so
    /// the caller can log them; they should generally not be fatal.
    pub fn start_hsm_service(&self) -> Result<(), String> {
        let Some(ref hsm) = self.hsm_provider else {
            return Ok(());
        };
        let mut h = hsm.lock().map_err(|_| "HSM lock poisoned".to_string())?;
        match h.start_service() {
            Ok(port) => {
                tracing::info!(port, "HSM service started");
                Ok(())
            }
            Err(hsm::HsmError::AlreadyRunning) => Ok(()),
            Err(e) => Err(format!("start HSM service: {e}")),
        }
    }

    /// Stop and re-spawn the HSM service. Used after provisioning so the
    /// daemon picks up the freshly-written keystore. NotRunning on stop
    /// is benign (we just spawn fresh).
    pub fn restart_hsm_service(&self) -> Result<(), String> {
        let Some(ref hsm) = self.hsm_provider else {
            return Ok(());
        };
        let mut h = hsm.lock().map_err(|_| "HSM lock poisoned".to_string())?;
        match h.stop_service() {
            Ok(()) | Err(hsm::HsmError::NotRunning) => {}
            Err(e) => tracing::warn!("stop HSM service before restart: {e}"),
        }
        match h.start_service() {
            Ok(port) => {
                tracing::info!(port, "HSM service restarted");
                Ok(())
            }
            Err(e) => Err(format!("restart HSM service: {e}")),
        }
    }

    pub fn running_bank(
        &self,
    ) -> Result<Bank, std::sync::PoisonError<std::sync::MutexGuard<'_, Bank>>> {
        self.running_bank.lock().map(|g| *g)
    }

    pub fn nv_lock(
        &self,
    ) -> Result<
        std::sync::MutexGuard<'_, NvStore<D>>,
        std::sync::PoisonError<std::sync::MutexGuard<'_, NvStore<D>>>,
    > {
        self.nv.lock()
    }

    pub fn nv_lock_mut(
        &self,
    ) -> Result<
        std::sync::MutexGuard<'_, NvStore<D>>,
        std::sync::PoisonError<std::sync::MutexGuard<'_, NvStore<D>>>,
    > {
        self.nv.lock()
    }

    /// Returns the HSM provisioning state if an HSM provider is wired up.
    /// `None` if no provider configured.
    pub fn hsm_provisioning_state(&self) -> Option<Result<hsm::ProvisioningState, hsm::HsmError>> {
        self.hsm_provider
            .as_ref()
            .map(|p| p.lock().unwrap().provisioning_state())
    }

    /// Drop any in-flight flash session state. Safe to call when no session
    /// is in flight (no-op). Does NOT undo a finalized install (bank pointer
    /// stays where it was) — that's the caller's responsibility, gated by
    /// `FlashCaps.abortable_after_finalize`.
    pub fn clear_flash_session(&self) {
        *self.flash_session.lock().unwrap() = None;
        *self.flash_transfer.lock().unwrap() = None;
        *self.upload_phase.lock().unwrap() = None;
        self.packages.lock().unwrap().clear();
        self.manifests.lock().unwrap().clear();
        self.payloads.lock().unwrap().clear();
        self.manifest_describe.lock().unwrap().clear();
    }

    /// Whether a flash session is currently in flight.
    ///
    /// Used by destructive ops (e.g. factory_reset) that must refuse rather
    /// than corrupt mid-write banks.
    pub fn flash_in_progress(&self) -> bool {
        self.flash_session.lock().unwrap().is_some()
    }

    /// True if the in-flight flash session has progressed past finalize
    /// (i.e. the staged bank is now the next-boot bank, awaiting reset).
    pub fn flash_is_finalized(&self) -> bool {
        let ft = self.flash_transfer.lock().unwrap();
        match ft.as_ref().map(|t| t.state) {
            Some(FlashState::AwaitingReboot)
            | Some(FlashState::Activated)
            | Some(FlashState::Committed)
            | Some(FlashState::RolledBack) => true,
            _ => false,
        }
    }

    pub fn ensure_flash_can_start(&self) -> BackendResult<()> {
        self.require_flash_access()?;

        if !self.config.single_bank {
            let nv = self
                .nv
                .lock()
                .map_err(|_| BackendError::Internal("nv lock".into()))?;
            let state = nv
                .read_boot_state()
                .ok_or_else(|| BackendError::Internal("no boot state".into()))?;
            let idx = self.bank_set.as_index();
            if !state.banks[idx].committed {
                return Err(BackendError::Busy(format!(
                    "bank set {:?} is in trial mode (active={:?}, uncommitted) — \
                     commit or rollback the pending upgrade before starting a new one",
                    self.bank_set, state.banks[idx].active_bank
                )));
            }
        }

        Ok(())
    }

    // =================================================================
    // Separate manifest + payload upload methods (new flash path)
    // =================================================================

    /// Upload a manifest (small CBOR envelope without integrated payloads).
    /// Validates signature + anti-rollback. Returns manifest_id.
    pub fn receive_manifest(&self, data: &[u8]) -> BackendResult<String> {
        self.require_flash_access()?;

        let min_security_ver = {
            let nv = self
                .nv
                .lock()
                .map_err(|_| BackendError::Internal("lock".into()))?;
            let rb = *self.running_bank.lock().unwrap();
            nv.read_fw_meta(self.bank_set, rb)
                .map(|m| m.min_security_ver)
                .unwrap_or(0)
        };

        let _validated = crate::streaming::validate_manifest(
            data,
            self.manifest_provider.as_ref(),
            min_security_ver,
        )?;

        let id = self.next_id();
        let mut manifests = self.manifests.lock().unwrap();
        manifests.insert(
            id.clone(),
            StoredManifest {
                raw_bytes: data.to_vec(),
            },
        );

        tracing::info!(manifest_id = %id, "manifest uploaded and validated");
        Ok(id)
    }

    /// Upload a raw payload (encrypted bytes, no CBOR).
    /// Streams to disk + computes SHA256. Returns payload_id.
    pub async fn receive_payload_stream(
        &self,
        stream: PackageStream,
        filename: Option<&str>,
    ) -> BackendResult<String> {
        let id = self.next_id();
        let dir = self
            .images_dir
            .as_ref()
            .ok_or_else(|| BackendError::Internal("no images_dir configured".into()))?;

        let fname = filename.unwrap_or("payload");
        let path = dir.join(format!("upload-{id}-{fname}"));

        let (size, _sha256) = crate::streaming::save_raw_payload(stream, &path).await?;

        let mut payloads = self.payloads.lock().unwrap();
        payloads.insert(id.clone(), StoredPayload { path });

        tracing::info!(payload_id = %id, size, "payload uploaded to disk");
        Ok(id)
    }

    /// Flash using a pre-uploaded manifest + payload(s).
    /// Processes each payload through decrypt → decompress → verify → write.
    pub fn start_flash_multi(
        &self,
        manifest_id: &str,
        payload_ids: &std::collections::HashMap<String, String>, // uri → payload_id
    ) -> BackendResult<String> {
        let manifests = self.manifests.lock().unwrap();
        let manifest = manifests.get(manifest_id).ok_or_else(|| {
            BackendError::InvalidRequest(format!("manifest {manifest_id} not found"))
        })?;

        let payloads = self.payloads.lock().unwrap();

        // Parse manifest to get component info
        let envelope = sumo_codec::decode::decode_envelope(&manifest.raw_bytes)
            .map_err(|e| BackendError::Internal(format!("decode manifest: {e:?}")))?;
        let suit_manifest = sumo_onboard::manifest::Manifest { envelope };

        let key_unwrap = self.manifest_provider.key_unwrap_for_decryption();

        let target_bank = self.determine_target_bank()?;
        let bank_dir = self
            .target_bank_dir(target_bank)
            .ok_or_else(|| BackendError::Internal("no images_dir configured".into()))?;
        std::fs::create_dir_all(&bank_dir)
            .map_err(|e| BackendError::Internal(format!("create {}: {e}", bank_dir.display())))?;

        // Process each payload
        for (uri, payload_id) in payload_ids {
            let stored_payload = payloads.get(payload_id).ok_or_else(|| {
                BackendError::InvalidRequest(format!("payload {payload_id} not found"))
            })?;

            // Find component index by URI
            let comp_count = suit_manifest.component_count();
            let comp_idx = (0..comp_count)
                .find(|&i| {
                    suit_manifest
                        .uri(i)
                        .map(|u| u == uri.as_str())
                        .unwrap_or(false)
                })
                .ok_or_else(|| {
                    BackendError::InvalidRequest(format!("no component with uri={uri} in manifest"))
                })?;

            let expected_digest = suit_manifest
                .image_digest(comp_idx)
                .map(|d| d.0.bytes.clone())
                .ok_or_else(|| {
                    BackendError::Internal(format!("no digest for component {comp_idx}"))
                })?;

            let output_path = bank_dir.join(crate::bank_spec::payload_target_name(
                self.bank_spec.layout,
                uri.as_str(),
            ));

            tracing::info!(
                uri = %uri,
                component = comp_idx,
                payload = %stored_payload.path.display(),
                output = %output_path.display(),
                "processing payload"
            );

            // `size` is the input file (compressed); the function returns the
            // uncompressed/written size. Cheap fs::metadata for context.
            let compressed = std::fs::metadata(&stored_payload.path)
                .map(|m| m.len())
                .unwrap_or(0);
            let process_started = std::time::Instant::now();
            let (image_size, _hash) = crate::streaming::process_raw_payload(
                &stored_payload.path,
                &manifest.raw_bytes,
                comp_idx,
                key_unwrap.as_deref(),
                &expected_digest,
                &output_path,
            )
            .map_err(|e| BackendError::Internal(format!("payload processing ({uri}): {e}")))?;
            let process_elapsed = process_started.elapsed();

            let compressed_mb = compressed as f64 / 1_048_576.0;
            let uncompressed_mb = image_size as f64 / 1_048_576.0;
            let secs = process_elapsed.as_secs_f64();
            let mb_per_sec = if secs > 0.0 {
                uncompressed_mb / secs
            } else {
                0.0
            };
            tracing::info!(
                uri = %uri,
                elapsed_ms = process_elapsed.as_millis() as u64,
                "payload written: {} ({:.2} MB compressed → {:.2} MB at {:.2} MB/s)",
                output_path.display(),
                compressed_mb, uncompressed_mb, mb_per_sec,
            );
        }

        // Create a validated result for the OTA install
        let transfer_id = self.next_id();
        Ok(transfer_id)
    }

    /// Handle manifest upload (first file in flash session).
    async fn handle_manifest_upload(
        &self,
        stream: PackageStream,
        _content_length: Option<u64>,
    ) -> BackendResult<String> {
        use futures::StreamExt;

        // Buffer the manifest entirely (it's small, <100KB).  Hash
        // as we go so `verify_part` can compare against the SOVD
        // layer's upload-time SHA-256.
        use sha2::Digest;
        let mut data = Vec::new();
        let mut hasher = sha2::Sha256::new();
        let mut stream = stream;
        while let Some(chunk) = stream.next().await {
            let bytes = chunk.map_err(|e| BackendError::Internal(format!("stream: {e}")))?;
            hasher.update(&bytes);
            data.extend_from_slice(&bytes);
            if data.len() > 100 * 1024 {
                return Err(BackendError::InvalidRequest(
                    "manifest too large (>100KB)".into(),
                ));
            }
        }

        tracing::info!(size = data.len(), "manifest uploaded, validating");

        // Validate
        let min_security_ver = {
            let nv = self
                .nv
                .lock()
                .map_err(|_| BackendError::Internal("lock".into()))?;
            let rb = *self.running_bank.lock().unwrap();
            nv.read_fw_meta(self.bank_set, rb)
                .map(|m| m.min_security_ver)
                .unwrap_or(0)
        };

        let validated = crate::streaming::validate_manifest(
            &data,
            self.manifest_provider.as_ref(),
            min_security_ver,
        )?;

        // Check if this is an integrated envelope (has inline payloads)
        let envelope = sumo_codec::decode::decode_envelope(&data)
            .map_err(|e| BackendError::Internal(format!("decode manifest: {e:?}")))?;
        let has_integrated = !envelope.integrated_payloads.is_empty();
        let manifest = sumo_onboard::manifest::Manifest { envelope };
        let total_components = manifest.component_count();

        let id = self.next_id();

        // Cache the SUIT-derived Table-261 facts keyed by this upload's
        // file_id, so `describe_update_package` can enrich GET /updates/{id}
        // later (the raw envelope is dropped after this; describe-time
        // re-parsing isn't possible). `id` is exactly the file_id the SOVD
        // wire records for the `"manifest"` part.
        {
            let meta = extract_describe_meta(&manifest, &validated.version_display);
            self.manifest_describe
                .lock()
                .unwrap()
                .insert(id.clone(), meta);
        }

        if has_integrated {
            // Integrated envelope (HSM keys, small packages) — all data present.
            // Validate and stage. Actual installation happens at ecu_reset.
            tracing::info!(manifest_id = %id, "integrated envelope — validating and staging");

            let full_validated = self
                .manifest_provider
                .validate(&data, min_security_ver)
                .map_err(|e| BackendError::InvalidRequest(format!("manifest: {e}")))?;

            // Store as verified+staged package (ready for install at reset time)
            {
                let mut packages = self.packages.lock().unwrap();
                packages.insert(
                    id.clone(),
                    StoredPackage {
                        id: id.clone(),
                        validated: full_validated,
                        status: PackageStatus::Verified,
                    },
                );
            }
            let upload_sha256: [u8; 32] = hasher.clone().finalize().into();
            self.uploaded_parts
                .lock()
                .unwrap()
                .insert(id.clone(), UploadedPartLocation::Manifest { upload_sha256 });

            // Session complete — no payload uploads needed
            {
                let mut session = self.flash_session.lock().unwrap();
                *session = Some(FlashSessionState::Complete);
            }

            // Flash transfer → AwaitingActivation (staged, ready for finalize + reset)
            {
                let mut ft = self.flash_transfer.lock().unwrap();
                if let Some(ref mut t) = *ft {
                    t.state = FlashState::AwaitingActivation;
                    t.package_id = id.clone();
                }
            }

            // Self-sign the staged bank so external secure boot can
            // validate it before launch. See `ivd_sign_staged_bank`
            // for soft-skip policy (no-op when HSM has no
            // ivd-signing slot yet).
            let target_bank = self.determine_target_bank()?;
            // Seed unstreamed files from the active bank so the IVD
            // signature below covers a complete bank, not a partial
            // one. No-op for full updates / single-bank / factory.
            self.seed_target_from_active(target_bank)?;
            self.ivd_sign_staged_bank(target_bank)?;

            return Ok(id);
        } else {
            // Manifest-only — wait for separate payload uploads
            tracing::info!(
                manifest_id = %id,
                components = total_components,
                "manifest validated — awaiting {} payload(s)",
                total_components,
            );

            // Store as package so finalize_flash can find it
            {
                let mut packages = self.packages.lock().unwrap();
                packages.insert(
                    id.clone(),
                    StoredPackage {
                        id: id.clone(),
                        validated: validated.clone(),
                        status: PackageStatus::Verified,
                    },
                );
            }
            let upload_sha256: [u8; 32] = hasher.clone().finalize().into();
            self.uploaded_parts
                .lock()
                .unwrap()
                .insert(id.clone(), UploadedPartLocation::Manifest { upload_sha256 });

            // Set package_id on flash transfer
            {
                let mut ft = self.flash_transfer.lock().unwrap();
                if let Some(ref mut t) = *ft {
                    t.package_id = id.clone();
                }
            }

            let mut session = self.flash_session.lock().unwrap();
            *session = Some(FlashSessionState::AwaitingPayload {
                manifest_bytes: data,
                validated,
                next_component: 0,
                total_components,
            });
        }

        Ok(id)
    }

    /// Handle payload upload (subsequent files in flash session).
    /// Streams directly through decrypt → decompress → verify → write to bank.
    async fn handle_payload_upload(
        &self,
        stream: PackageStream,
        _content_length: Option<u64>,
    ) -> BackendResult<String> {
        // Extract session state
        let (manifest_bytes, comp_idx, total) = {
            let session = self.flash_session.lock().unwrap();
            match session.as_ref() {
                Some(FlashSessionState::AwaitingPayload {
                    manifest_bytes,
                    next_component,
                    total_components,
                    ..
                }) => (manifest_bytes.clone(), *next_component, *total_components),
                _ => {
                    return Err(BackendError::InvalidRequest(
                        "no active flash session".into(),
                    ))
                }
            }
        };

        let key_unwrap = self.manifest_provider.key_unwrap_for_decryption();

        // Parse manifest for this component's info
        let envelope = sumo_codec::decode::decode_envelope(&manifest_bytes)
            .map_err(|e| BackendError::Internal(format!("decode manifest: {e:?}")))?;
        let manifest = sumo_onboard::manifest::Manifest { envelope };

        let expected_digest = manifest
            .image_digest(comp_idx)
            .map(|d| d.0.bytes.clone())
            .ok_or_else(|| BackendError::Internal(format!("no digest for component {comp_idx}")))?;

        let uri = manifest.uri(comp_idx).unwrap_or("#firmware").to_string();

        let target_bank = self.determine_target_bank()?;
        let bank_dir = self
            .target_bank_dir(target_bank)
            .ok_or_else(|| BackendError::Internal("no images_dir configured".into()))?;
        std::fs::create_dir_all(&bank_dir)
            .map_err(|e| BackendError::Internal(format!("create {}: {e}", bank_dir.display())))?;

        let target_name = crate::bank_spec::payload_target_name(self.bank_spec.layout, &uri);
        let output_path = bank_dir.join(&target_name);

        tracing::info!(
            component = comp_idx,
            uri = %uri,
            output = %output_path.display(),
            "processing payload {}/{}",
            comp_idx + 1, total,
        );

        // Stream straight through: network → decrypt → decompress →
        // hash → final file. No on-disk ciphertext scratch — flash I/O
        // is the dominant cost on the device and writing the payload
        // twice (once as .tmp, once unpacked) doubles it for nothing.
        let process_started = std::time::Instant::now();
        let (inbound, image_size, image_hash) = crate::streaming::process_payload_stream(
            stream,
            manifest_bytes.clone(),
            comp_idx,
            key_unwrap.clone(),
            expected_digest.clone(),
            output_path.clone(),
        )
        .await?;
        let process_elapsed = process_started.elapsed();

        // Record the freshly-hashed file for `ivd_sign_staged_bank` so
        // it doesn't need to re-walk + re-hash this payload from disk
        // when sealing the bank.
        {
            let mut ft = self.flash_transfer.lock().unwrap();
            if let Some(ref mut t) = *ft {
                t.streamed_files.push(hsm::ivd::IvdFile {
                    relative_path: target_name.clone(),
                    sha256: image_hash.to_vec(),
                    size: image_size as u64,
                });
            }
        }

        let compressed_mb = inbound as f64 / 1_048_576.0;
        let uncompressed_mb = image_size as f64 / 1_048_576.0;
        let secs = process_elapsed.as_secs_f64();
        // Throughput is uncompressed bytes per second — the sustained
        // decrypt+decompress+write rate, which is what determines wall time.
        let mb_per_sec = if secs > 0.0 {
            uncompressed_mb / secs
        } else {
            0.0
        };
        tracing::info!(
            component = comp_idx,
            uri = %uri,
            elapsed_ms = process_elapsed.as_millis() as u64,
            "payload written: {} ({:.2} MB compressed → {:.2} MB at {:.2} MB/s)",
            output_path.display(),
            compressed_mb, uncompressed_mb, mb_per_sec,
        );

        // Advance session state
        let next = comp_idx + 1;
        let all_done = {
            let mut session = self.flash_session.lock().unwrap();
            if next >= total {
                // All payloads received
                *session = Some(FlashSessionState::Complete);
                tracing::info!("all payloads received — ready for transferexit");

                // Update flash transfer state to AwaitingActivation
                let mut ft = self.flash_transfer.lock().unwrap();
                if let Some(ref mut t) = *ft {
                    t.state = FlashState::AwaitingActivation;
                    t.image_size = image_size as u64;
                }
                true
            } else {
                // Update to next component
                if let Some(FlashSessionState::AwaitingPayload {
                    ref mut next_component,
                    ..
                }) = *session
                {
                    *next_component = next;
                }
                false
            }
        };

        if all_done {
            // Bank dir is content-final; IVD-sign before the caller
            // proceeds to finalize_flash. See `ivd_sign_staged_bank`.
            let target_bank = self.determine_target_bank()?;
            // Seed unstreamed files from the active bank so the IVD
            // signature below covers a complete bank, not a partial
            // one. No-op for full updates / single-bank / factory.
            self.seed_target_from_active(target_bank)?;
            self.ivd_sign_staged_bank(target_bank)?;
        }

        let id = self.next_id();
        self.uploaded_parts.lock().unwrap().insert(
            id.clone(),
            UploadedPartLocation::OnDisk {
                path: output_path.clone(),
                inner_sha256: image_hash,
            },
        );
        Ok(id)
    }

    fn require_flash_access(&self) -> BackendResult<()> {
        let session = self.session.lock().unwrap();
        if *session != SessionState::Programming {
            return Err(BackendError::SessionRequired("programming".to_string()));
        }
        let security = self.security.lock().unwrap();
        if security.phase != SecurityPhase::Unlocked {
            return Err(BackendError::SecurityRequired(1));
        }
        Ok(())
    }

    pub(crate) fn nv_bytes_to_string(data: &[u8]) -> String {
        let end = data.iter().position(|&c| c == 0).unwrap_or(data.len());
        String::from_utf8_lossy(&data[..end]).to_string()
    }

    /// Send a restart request to vm-service over its Unix socket.
    ///
    /// Reads back the HTTP status line so axum gets a chance to fully
    /// process the request before our side closes the socket. Earlier
    /// versions of this dropped the stream right after `write_all`,
    /// which raced under campaign load: when the orchestrator issues
    /// vm1+vm2 resets in parallel, the two `notify_vm_service` calls
    /// arrived back-to-back; axum sometimes saw EOF before parsing the
    /// second request, so vm1 never got started.
    ///
    /// vm-service's `restart_vm` returns 200 the moment it has
    /// initiated the restart (it does NOT wait for QEMU to fully boot),
    /// so this read is bounded — the orchestrator still polls
    /// activation state separately to know when the guest is healthy.
    ///
    /// `action` is the URL verb: "restart" when the VM was already running
    /// (graceful PowerCommand::Shutdown → start), or "start" when the VM
    /// was offline pre-reset (factory provision, post-crash) so callers
    /// don't pay for a phantom shutdown step and the GUI doesn't display
    /// a misleading "Shutting Down vm2" tile for a guest that never ran.
    async fn notify_vm_service(addr: &str, vm_name: &str, action: &str) -> Result<(), String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| format!("connect to vm-service: {e}"))?;

        let request = format!(
            "POST /vms/{vm_name}/{action} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Length: 0\r\n\
             Connection: close\r\n\
             \r\n"
        );

        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("write to vm-service: {e}"))?;

        // Read the status line (with a generous timeout — the handler
        // returns once restart is initiated, ~100s of ms).
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(15), stream.read(&mut buf))
            .await
            .map_err(|_| "vm-service didn't respond within 15s".to_string())?
            .map_err(|e| format!("read from vm-service: {e}"))?;

        let resp = String::from_utf8_lossy(&buf[..n]);
        let status_line = resp.lines().next().unwrap_or("(empty)");
        if status_line.contains("200") {
            Ok(())
        } else {
            Err(format!("vm-service returned: {status_line}"))
        }
    }

    /// Whether the guest backing this component has finished its
    /// post-update boot. Used by `get_activation_state` to lazily
    /// promote `Verifying → Activated`.
    ///
    /// True when:
    /// - there is no guest concept (no vm-service socket configured), or
    /// - vm-service reports the guest as fresh AND live:
    ///   * `status == "running"` — vm-service has seen the hb_seq counter
    ///     advance recently (its 5 s liveness window catches the
    ///     stale-heartbeat case where the daemon stopped publishing);
    ///   * `guest_state == 1` (Running) — the daemon itself declares
    ///     services-ready;
    ///   * `boot_id != baseline_boot_id` — the heartbeat we're reading
    ///     is from the post-reset lifetime, not stale shmem from the
    ///     previous one. (`boot_id` is randomly generated per guest
    ///     lifetime and is part of every heartbeat frame.)
    ///   * If no baseline was captured (VM was offline pre-reset, e.g.
    ///     factory provision) we accept any running heartbeat.
    async fn guest_is_running(&self) -> bool {
        let socket = match &self.vm_service_addr {
            Some(s) => s,
            None => return true,
        };
        let baseline = self
            .flash_transfer
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|t| t.verify_baseline_boot_id);
        let Some(h) = query_vm_health(socket, &self.entity_info.id).await else {
            return false;
        };
        // vm-service flips status off "running" when hb_seq hasn't
        // advanced within HEARTBEAT_STALE_AFTER — guards against a
        // daemon that crashed mid-update and left stale shmem behind.
        if h.status != "running" || h.guest_state != 1 {
            return false;
        }
        match baseline {
            Some(b) => h.boot_id != b,
            None => true,
        }
    }
}

// ---------------------------------------------------------------------------
// NvWriteGuard — RAII wrapper around the NV mutex for write sites.
//
// Holds the NV mutex for as long as the guard lives. On drop, refreshes
// the DID cache before releasing the mutex — so callers don't have to
// remember to call refresh_did_cache_locked at every write site, and
// readers that wake up after the mutex drops always see a cache
// consistent with the just-written NV state.
//
// Use `VmBackend::nv_write()` to acquire. Read sites should keep using
// `self.nv.lock()` directly — they don't need the refresh, and going
// through the guard would do useless work.
// ---------------------------------------------------------------------------

struct NvWriteGuard<'a, D: BlockDevice + Send + 'static> {
    backend: &'a VmBackend<D>,
    /// `Option` so `Drop` can take it via `Option::take()` and refresh
    /// against the unwrapped guard before releasing the mutex.
    inner: Option<std::sync::MutexGuard<'a, NvStore<D>>>,
}

impl<'a, D: BlockDevice + Send + 'static> std::ops::Deref for NvWriteGuard<'a, D> {
    type Target = NvStore<D>;
    fn deref(&self) -> &NvStore<D> {
        self.inner.as_ref().expect("guard active")
    }
}

impl<'a, D: BlockDevice + Send + 'static> std::ops::DerefMut for NvWriteGuard<'a, D> {
    fn deref_mut(&mut self) -> &mut NvStore<D> {
        self.inner.as_mut().expect("guard active")
    }
}

impl<'a, D: BlockDevice + Send + 'static> Drop for NvWriteGuard<'a, D> {
    fn drop(&mut self) {
        if let Some(ref guard) = self.inner {
            // Refresh while still holding the mutex — readers waking up
            // after this point see new NV + new cache, never half-state.
            self.backend.refresh_did_cache_locked(&**guard);
        }
        // `inner` drops normally → mutex released.
    }
}

// ---------------------------------------------------------------------------
// DiagnosticBackend implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl<D: BlockDevice + Send + 'static> DiagnosticBackend for VmBackend<D> {
    fn entity_info(&self) -> &EntityInfo {
        &self.entity_info
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    /// F.D5: report the lifecycle shape so SOVDd's /campaigns
    /// coordinator orders Banked-vs-Singleshot finalize correctly
    /// (sw-update-architecture.md §5).  HSM and other single-bank
    /// targets are singleshot; everything else (host-os, VMs, RT
    /// core, slave-ECU components) is banked.
    fn update_shape(&self) -> &'static str {
        if self.config.single_bank {
            "singleshot"
        } else {
            "banked"
        }
    }

    // --- Data ---

    async fn list_parameters(&self) -> BackendResult<Vec<ParameterInfo>> {
        let nv = self
            .nv
            .lock()
            .map_err(|_| BackendError::Internal("lock".into()))?;
        let comp_id = &self.entity_info.id;

        let has_health = self.vm_service_addr.is_some();
        let mut params: Vec<ParameterInfo> = DID_REGISTRY
            .iter()
            .filter(|d| {
                has_health || (d.did != did::DID_GUEST_STATE && d.did != did::DID_HEARTBEAT_SEQ)
            })
            .map(|d| ParameterInfo {
                id: d.id.to_string(),
                name: d.name.to_string(),
                description: None,
                unit: None,
                data_type: Some(d.data_type.to_string()),
                read_only: !d.writable,
                href: format!("/vehicle/v1/components/{comp_id}/data/{}", d.id),
                did: Some(format!("{:04X}", d.did)),
                category: Some(DataCategory::from_did(d.did)),
            })
            .collect();

        // Add runtime DIDs
        {
            let active = *self.running_bank.lock().unwrap();
            if let Some(runtime) = nv.read_runtime(self.bank_set, active) {
                for i in 0..runtime.did_count as usize {
                    let did_num = runtime.dids[i].did;
                    if DID_REGISTRY.iter().any(|d| d.did == did_num) {
                        continue;
                    }
                    let id = format!("runtime_{:04X}", did_num);
                    params.push(ParameterInfo {
                        id: id.clone(),
                        name: format!("Runtime DID 0x{:04X}", did_num),
                        description: None,
                        unit: None,
                        data_type: Some("bytes".to_string()),
                        read_only: false,
                        href: format!("/vehicle/v1/components/{comp_id}/data/{id}"),
                        did: Some(format!("{:04X}", did_num)),
                        category: Some(DataCategory::from_did(did_num)),
                    });
                }
            }
        }

        // Vendor data parameter: the running/committed bank's signed IVD
        // manifest (per-file inventory + identity + signature). Advertised
        // only when a verifiable manifest actually exists — absent on the
        // no-HSM smoke path or a never-flashed bank, so we don't fabricate
        // a parameter that would 404 on read.
        let running = *self.running_bank.lock().unwrap();
        if self.verified_bank_manifest(running).is_some() {
            params.push(ParameterInfo {
                id: INSTALLED_MANIFEST_PARAM_ID.to_string(),
                name: "Installed firmware manifest (signed IVD)".to_string(),
                description: Some(
                    "Committed bank's signature-verified IVD manifest: \
                     per-file name + sha256 inventory, firmware SW identity, \
                     and the device signature + manifest bytes (base64) for \
                     downstream re-verification."
                        .to_string(),
                ),
                unit: None,
                data_type: Some("object".to_string()),
                read_only: true,
                href: format!(
                    "/vehicle/v1/components/{comp_id}/data/{INSTALLED_MANIFEST_PARAM_ID}"
                ),
                did: None,
                category: Some(DataCategory::IdentData),
            });
        }

        Ok(params)
    }

    async fn read_data(&self, param_ids: &[String]) -> BackendResult<Vec<DataValue>> {
        // No NV mutex acquired here. Health DIDs go through query_vm_health
        // (a fast HTTP loopback to vm-service); all other DIDs are served
        // from the in-memory `did_cache`, populated at startup and kept in
        // sync after every NV write. This eliminates the NV-mutex
        // contention that turned the campaign-viewer's poll cycle into
        // a 10-15 s blocked dance during flash on QNX/eMMC.
        let mut values = Vec::new();

        for param_id in param_ids {
            // Vendor parameter: the running/committed bank's signed IVD
            // manifest. Intercepted before `resolve_param` (which only
            // knows DID-registry / hex ids). 404 when no committed manifest
            // exists — never fabricated.
            if param_id == INSTALLED_MANIFEST_PARAM_ID {
                let running = *self.running_bank.lock().unwrap();
                let vm = self.verified_bank_manifest(running).ok_or_else(|| {
                    BackendError::EntityNotFound(format!(
                        "{INSTALLED_MANIFEST_PARAM_ID}: no committed IVD manifest for {} bank {:?}",
                        self.entity_info.id, running
                    ))
                })?;
                values.push(DataValue {
                    id: param_id.clone(),
                    name: "Installed firmware manifest (signed IVD)".to_string(),
                    value: installed_manifest_json(&vm),
                    unit: None,
                    timestamp: Utc::now(),
                    raw: None,
                    did: None,
                    length: None,
                });
                continue;
            }

            let (did_num, reg) = resolve_param(param_id)
                .ok_or_else(|| BackendError::ParameterNotFound(param_id.clone()))?;

            // Health DIDs — query vm-service HTTP API, or fall back to a
            // configured health probe for activator-backed components that
            // have no vm-service (RT/M7 surfaces its state via `m7loader -q`
            // wrapped by `HealthProbe`).
            if did_num == did::DID_GUEST_STATE || did_num == did::DID_HEARTBEAT_SEQ {
                let health = match self.vm_service_addr.as_ref() {
                    Some(sock) => query_vm_health(sock, &self.entity_info.id).await,
                    None => self.health_probe.as_ref().and_then(|p| p.probe()),
                };
                let (value, raw) = match (did_num, &health) {
                    (did::DID_GUEST_STATE, Some(h)) => {
                        let s = guest_state_str(h.guest_state);
                        (
                            serde_json::Value::String(s.to_string()),
                            format!("{:08x}", h.guest_state),
                        )
                    }
                    (did::DID_GUEST_STATE, None) => (
                        serde_json::Value::String("offline".to_string()),
                        "ffffffff".to_string(),
                    ),
                    (did::DID_HEARTBEAT_SEQ, Some(h)) => {
                        (serde_json::json!(h.hb_seq), format!("{:08x}", h.hb_seq))
                    }
                    (did::DID_HEARTBEAT_SEQ, None) => {
                        (serde_json::json!(0), "00000000".to_string())
                    }
                    _ => unreachable!(),
                };
                let name = reg.map(|r| r.name).unwrap_or(param_id.as_str());
                values.push(DataValue {
                    id: param_id.clone(),
                    name: name.to_string(),
                    value,
                    unit: None,
                    timestamp: Utc::now(),
                    raw: Some(raw),
                    did: Some(format!("{:04X}", did_num)),
                    length: Some(4),
                });
                continue;
            }

            let cached = self
                .did_cache
                .read()
                .expect("did_cache poisoned")
                .get(&did_num)
                .cloned();
            match cached {
                Some(bytes) => {
                    let value = did_value_to_json(did_num, &bytes, reg);
                    let raw_hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                    let name = reg.map(|r| r.name).unwrap_or(param_id.as_str());
                    values.push(DataValue {
                        id: param_id.clone(),
                        name: name.to_string(),
                        value,
                        unit: None,
                        timestamp: Utc::now(),
                        raw: Some(raw_hex),
                        did: Some(format!("{:04X}", did_num)),
                        length: Some(bytes.len()),
                    });
                }
                None => {
                    return Err(BackendError::ParameterNotFound(param_id.clone()));
                }
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

        let mut nv = self.nv_write()?;
        match did::write_did(&mut *nv, self.bank_set, did_num, value) {
            Ok(true) => Ok(()),
            Ok(false) => Err(BackendError::Internal("runtime DID store full".into())),
            Err(e) => Err(BackendError::Internal(e.to_string())),
        }
    }

    // --- Faults ---

    async fn get_faults(&self, _filter: Option<&FaultFilter>) -> BackendResult<FaultsResult> {
        let nv = self
            .nv
            .lock()
            .map_err(|_| BackendError::Internal("lock".into()))?;
        let active = *self.running_bank.lock().unwrap();
        let runtime = nv.read_runtime(self.bank_set, active).unwrap_or_default();

        let faults: Vec<Fault> = (0..runtime.dtc_count as usize)
            .map(|i| {
                let dtc = &runtime.dtcs[i];
                let code = format!("{:06X}", dtc.dtc_number);
                let active = dtc.status & 0x01 != 0;
                Fault {
                    id: format!("dtc_{code}"),
                    code: code.clone(),
                    severity: if active {
                        FaultSeverity::Error
                    } else {
                        FaultSeverity::Warning
                    },
                    message: format!("DTC {code}"),
                    category: None,
                    first_occurrence: None,
                    last_occurrence: None,
                    occurrence_count: None,
                    active,
                    status: Some(serde_json::json!(dtc.status)),
                    href: format!(
                        "/vehicle/v1/components/{}/faults/dtc_{code}",
                        self.entity_info.id
                    ),
                }
            })
            .collect();

        Ok(FaultsResult {
            faults,
            status_availability_mask: None,
        })
    }

    async fn clear_faults(&self, _group: Option<u32>) -> BackendResult<ClearFaultsResult> {
        let mut nv = self.nv_write()?;
        let active = *self.running_bank.lock().unwrap();
        let mut runtime = nv.read_runtime(self.bank_set, active).unwrap_or_default();

        let cleared = runtime.dtc_count as u32;
        runtime.dtc_count = 0;
        runtime.dtcs = std::array::from_fn(|_| DtcEntry::default());

        nv.write_runtime(self.bank_set, active, &mut runtime)
            .map_err(|e| BackendError::Internal(e.to_string()))?;

        Ok(ClearFaultsResult {
            success: true,
            cleared_count: cleared,
            message: format!("Cleared {cleared} faults"),
        })
    }

    // --- Operations (stub) ---

    async fn list_operations(&self) -> BackendResult<Vec<OperationInfo>> {
        Ok(vec![])
    }

    async fn start_operation(
        &self,
        operation_id: &str,
        _params: &[u8],
    ) -> BackendResult<OperationExecution> {
        Err(BackendError::OperationNotFound(operation_id.to_string()))
    }

    // --- Update package catalog (ISO 17978-3 §7.18.3 Table 261) ---

    /// Enrich `GET /updates/{id}` from the uploaded SUIT manifest.
    ///
    /// Starts from the format-agnostic [`default_descriptor_from_context`]
    /// base, then overrides the fields the SUIT envelope genuinely provides:
    /// a meaningful `update_name`, optional release `notes`, and the
    /// `updated`/`affected` component entity-paths.
    ///
    /// The manifest's SUIT facts were cached when the `"manifest"` bulk-data
    /// part arrived, keyed by that part's `file_id`. We locate the
    /// `part_id == "manifest"` part in the context, look the facts up by its
    /// `file_id`, and enrich. Absent/garbled manifest → the default base is
    /// returned unchanged (the GET never errors). No locks are held across an
    /// `.await` (the lookup returns owned clones; there is no `.await` here).
    async fn describe_update_package(
        &self,
        ctx: &UpdatePackageContext<'_>,
    ) -> BackendResult<UpdatePackageDescriptor> {
        let mut desc = default_descriptor_from_context(ctx);

        // The orchestrator uploads the SUIT envelope as the part whose
        // part_id is exactly "manifest"; its file_id is the cache key.
        let Some(manifest_part) = ctx.parts.iter().find(|p| p.part_id == "manifest") else {
            return Ok(desc);
        };
        let Some((update_name, notes, component_paths)) =
            self.manifest_describe_facts(manifest_part.file_id)
        else {
            // No cached facts (parse failed, or this file_id isn't a
            // manifest) — keep the honest default.
            return Ok(desc);
        };

        if let Some(name) = update_name {
            desc.update_name = name;
        }
        if let Some(n) = notes {
            desc.notes = Some(n);
        }

        // The manifest names this component; the SOVD-addressable entity it
        // maps to is this backend's own component id (the bank set this
        // VmBackend serves). Report it as both updated (version changed) and
        // affected. `default_descriptor_from_context` already seeded
        // `affected_components` with this same path; set `updated_components`
        // only when the manifest actually carried component identifiers.
        if !component_paths.is_empty() {
            let entity_path = format!("/vehicle/v1/components/{}", self.entity_info.id);
            desc.updated_components = vec![entity_path.clone()];
            desc.affected_components = vec![entity_path];
        }

        Ok(desc)
    }

    // --- Package management ---

    async fn receive_package(&self, data: &[u8]) -> BackendResult<String> {
        self.require_flash_access()?;

        let min_security_ver = {
            let nv = self
                .nv
                .lock()
                .map_err(|_| BackendError::Internal("lock".into()))?;
            let rb = *self.running_bank.lock().unwrap();
            nv.read_fw_meta(self.bank_set, rb)
                .map(|m| m.min_security_ver)
                .unwrap_or(0)
        };

        let validated = self
            .manifest_provider
            .validate(data, min_security_ver)
            .map_err(|e| BackendError::InvalidRequest(format!("manifest validation: {e}")))?;

        if validated.bank_set != self.bank_set {
            return Err(BackendError::InvalidRequest(format!(
                "manifest targets {:?}, but this is {:?}",
                validated.bank_set, self.bank_set
            )));
        }

        let id = self.next_id();

        // Single-shot upload still carries the raw envelope here, so cache
        // the SUIT describe facts keyed by this file_id for GET /updates/{id}.
        if let Ok(envelope) = sumo_codec::decode::decode_envelope(data) {
            let manifest = sumo_onboard::manifest::Manifest { envelope };
            let meta = extract_describe_meta(&manifest, &validated.version_display);
            self.manifest_describe
                .lock()
                .unwrap()
                .insert(id.clone(), meta);
        }

        let mut packages = self.packages.lock().unwrap();
        packages.insert(
            id.clone(),
            StoredPackage {
                id: id.clone(),
                validated,
                status: PackageStatus::Verified,
            },
        );

        Ok(id)
    }

    async fn receive_package_stream(
        &self,
        stream: PackageStream,
        content_length: Option<u64>,
    ) -> BackendResult<String> {
        self.require_flash_access()?;

        // Check flash session state — determines how to handle this upload
        let session_state = {
            let session = self.flash_session.lock().unwrap();
            match session.as_ref() {
                Some(FlashSessionState::AwaitingManifest) => Some("manifest"),
                Some(FlashSessionState::AwaitingPayload { .. }) => Some("payload"),
                _ => None,
            }
        };

        match session_state {
            Some("manifest") => {
                return self.handle_manifest_upload(stream, content_length).await;
            }
            Some("payload") => {
                return self.handle_payload_upload(stream, content_length).await;
            }
            _ => {
                // No active flash session — legacy integrated envelope path
            }
        }

        // --- Legacy path: integrated SUIT envelope (HSM keys, etc.) ---

        let min_security_ver = {
            let nv = self
                .nv
                .lock()
                .map_err(|_| BackendError::Internal("lock".into()))?;
            let rb = *self.running_bank.lock().unwrap();
            nv.read_fw_meta(self.bank_set, rb)
                .map(|m| m.min_security_ver)
                .unwrap_or(0)
        };

        tracing::info!(
            bank_set = ?self.bank_set,
            content_length = ?content_length,
            "streaming package upload (legacy envelope)"
        );

        // Legacy single-POST envelope path doesn't go through start_flash, so
        // it has to set up the target bank dir itself (clear inactive bank +
        // wipe orphaned staged files) before streaming the payload.
        let target_bank = self.determine_target_bank()?;
        self.prepare_target_bank_dir(target_bank)?;

        let transfer_id = self.next_id();
        {
            let mut ft = self.flash_transfer.lock().unwrap();
            *ft = Some(FlashTransferState {
                transfer_id: transfer_id.clone(),
                package_id: String::new(),
                state: FlashState::Transferring,
                image_size: content_length.unwrap_or(0),
                verify_baseline_boot_id: None,
                streamed_files: Vec::new(),
            });
        }

        *self.upload_phase.lock().unwrap() = Some(FlashState::Transferring);

        let validated = match crate::streaming::process_envelope_stream(
            stream,
            self.manifest_provider.as_ref(),
            min_security_ver,
            self.images_dir.as_deref(),
            self.bank_set,
            &self.bank_spec,
            target_bank,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                *self.upload_phase.lock().unwrap() = None;
                let mut ft = self.flash_transfer.lock().unwrap();
                if let Some(ref mut t) = *ft {
                    t.state = FlashState::Failed;
                }
                return Err(e);
            }
        };

        *self.upload_phase.lock().unwrap() = None;
        {
            let mut ft = self.flash_transfer.lock().unwrap();
            if let Some(ref mut t) = *ft {
                t.state = FlashState::Preparing;
                // Hand the per-file hash inventory captured by the
                // streaming pipeline through to `ivd_sign_staged_bank`
                // so it can build the IVD manifest without re-reading
                // the bank from disk.
                t.streamed_files = validated.streamed_files.clone();
            }
        }

        let id = self.next_id();
        let mut packages = self.packages.lock().unwrap();
        packages.insert(
            id.clone(),
            StoredPackage {
                id: id.clone(),
                validated,
                status: PackageStatus::Verified,
            },
        );

        Ok(id)
    }

    async fn list_packages(&self) -> BackendResult<Vec<PackageInfo>> {
        let packages = self.packages.lock().unwrap();
        Ok(packages
            .values()
            .map(|p| PackageInfo {
                id: p.id.clone(),
                size: p.validated.image_data.len(),
                target_ecu: Some(self.entity_info.id.clone()),
                version: Some(p.validated.version_display.clone()),
                status: p.status,
                created_at: None,
            })
            .collect())
    }

    async fn get_package(&self, package_id: &str) -> BackendResult<PackageInfo> {
        let packages = self.packages.lock().unwrap();
        let p = packages
            .get(package_id)
            .ok_or_else(|| BackendError::EntityNotFound(package_id.to_string()))?;
        Ok(PackageInfo {
            id: p.id.clone(),
            size: p.validated.image_data.len(),
            target_ecu: Some(self.entity_info.id.clone()),
            version: Some(p.validated.version_display.clone()),
            status: p.status,
            created_at: None,
        })
    }

    async fn verify_package(&self, package_id: &str) -> BackendResult<VerifyResult> {
        let packages = self.packages.lock().unwrap();
        let p = packages
            .get(package_id)
            .ok_or_else(|| BackendError::EntityNotFound(package_id.to_string()))?;

        use sha2::{Digest, Sha256};
        let hash: [u8; 32] = Sha256::digest(&p.validated.image_data).into();
        let hash_hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();

        Ok(VerifyResult {
            valid: true,
            checksum: Some(hash_hex),
            algorithm: Some("sha256".to_string()),
            error: None,
        })
    }

    async fn verify_part(&self, file_id: &str, expected_sha256: &str) -> BackendResult<()> {
        use sha2::{Digest, Sha256};
        // Re-verification semantics:
        //
        // * Manifest part — the SOVD layer's `expected_sha256` is the
        //   outer (wire-bytes) hash recorded during PUT /bulk-data.
        //   We stored the same value at upload time; compare directly.
        //
        // * Detached payload — we cannot re-verify the outer hash
        //   without keeping the raw ciphertext bytes around (multi-MB
        //   per payload — flash I/O cost doubles).  Outer integrity
        //   was already validated during streaming.  Re-verify the
        //   inner hash instead: re-read the on-disk decrypted content
        //   and compare to the inner SHA-256 the streaming pipeline
        //   captured at write time (already cross-checked against the
        //   manifest's image_digest).  The SOVD-passed
        //   `expected_sha256` (outer) is informational only here.
        let location = {
            let parts = self.uploaded_parts.lock().unwrap();
            parts
                .get(file_id)
                .ok_or_else(|| {
                    BackendError::EntityNotFound(format!("no uploaded part with file_id {file_id}"))
                })
                .map(|loc| match loc {
                    UploadedPartLocation::Manifest { upload_sha256 } => {
                        UploadedPartLocation::Manifest {
                            upload_sha256: *upload_sha256,
                        }
                    }
                    UploadedPartLocation::OnDisk { path, inner_sha256 } => {
                        UploadedPartLocation::OnDisk {
                            path: path.clone(),
                            inner_sha256: *inner_sha256,
                        }
                    }
                })?
        };
        match location {
            UploadedPartLocation::Manifest { upload_sha256 } => {
                let stored = hex::encode(upload_sha256);
                if stored.eq_ignore_ascii_case(expected_sha256) {
                    Ok(())
                } else {
                    Err(BackendError::InvalidRequest(format!(
                        "verify_part {file_id}: outer sha256 mismatch — \
                         stored {stored}, expected {expected_sha256}",
                    )))
                }
            }
            UploadedPartLocation::OnDisk { path, inner_sha256 } => {
                let bytes = std::fs::read(&path).map_err(|e| {
                    BackendError::Internal(format!("verify_part read {}: {e}", path.display()))
                })?;
                let recomputed: [u8; 32] = Sha256::digest(&bytes).into();
                if recomputed == inner_sha256 {
                    Ok(())
                } else {
                    Err(BackendError::InvalidRequest(format!(
                        "verify_part {file_id}: inner sha256 mismatch on disk — \
                         recomputed {} vs captured {}",
                        hex::encode(recomputed),
                        hex::encode(inner_sha256)
                    )))
                }
            }
        }
    }

    async fn delete_package(&self, package_id: &str) -> BackendResult<()> {
        let mut packages = self.packages.lock().unwrap();
        packages
            .remove(package_id)
            .ok_or_else(|| BackendError::EntityNotFound(package_id.to_string()))?;
        Ok(())
    }

    // --- Flash ---

    async fn start_flash(&self) -> BackendResult<String> {
        self.ensure_flash_can_start()?;

        // Clear the target bank dir (and any orphaned staged files) BEFORE
        // any payload starts streaming in. Frees ~1 image worth of space on
        // the partition that's about to receive the new bank.
        let target_bank = self.determine_target_bank()?;
        self.prepare_target_bank_dir(target_bank)?;

        // Initialize flash session — next upload will be treated as manifest
        {
            let mut session = self.flash_session.lock().unwrap();
            *session = Some(FlashSessionState::AwaitingManifest);
        }

        // Clear stale packages from previous flash cycles so we don't
        // accidentally pick up an old verified package.
        {
            let mut packages = self.packages.lock().unwrap();
            packages.clear();
        }
        // Drop the previous cycle's part-location records; new uploads
        // re-populate as they arrive.
        self.uploaded_parts.lock().unwrap().clear();
        // Same for the manifest describe-cache — stale SUIT facts from a
        // prior flash must not leak into this session's catalog entry.
        self.manifest_describe.lock().unwrap().clear();

        let transfer_id = self.next_id();
        tracing::info!(transfer_id = %transfer_id, "flash session started — awaiting manifest upload");

        // Check if we already have a verified package (legacy integrated envelope path)
        let package_id = {
            let packages = self.packages.lock().unwrap();
            packages
                .iter()
                .find(|(_, p)| p.status == PackageStatus::Verified)
                .map(|(id, _)| id.clone())
        };

        // If no verified package yet, return the transfer_id.
        // Payloads will be processed as they arrive via receive_package_stream.
        let Some(package_id) = package_id else {
            let mut ft = self.flash_transfer.lock().unwrap();
            *ft = Some(FlashTransferState {
                transfer_id: transfer_id.clone(),
                package_id: String::new(),
                state: FlashState::Transferring,
                image_size: 0,
                verify_baseline_boot_id: None,
                streamed_files: Vec::new(),
            });
            return Ok(transfer_id);
        };
        let (meta, image_data, image_size, pre_sha256, pre_size, manifest_type, raw_envelope) = {
            let packages = self.packages.lock().unwrap();
            let p = packages
                .get(&package_id)
                .ok_or_else(|| BackendError::EntityNotFound(package_id.to_string()))?;
            let size = if let Some(s) = p.validated.image_size {
                s
            } else {
                p.validated.image_data.len() as u64
            };
            (
                p.validated.image_meta.clone(),
                p.validated.image_data.clone(),
                size,
                p.validated.image_sha256,
                p.validated.image_size,
                p.validated.manifest_type,
                p.validated.raw_envelope.clone(),
            )
        };

        // HSM key material — route to HsmProvider, skip normal image write
        if manifest_type == ManifestType::HsmKeys {
            let envelope = raw_envelope.as_deref().ok_or_else(|| {
                BackendError::Internal("HSM key manifest missing raw envelope".into())
            })?;
            let hsm = self.hsm_provider.as_ref().ok_or_else(|| {
                BackendError::Internal("no HSM provider configured for key provisioning".into())
            })?;
            {
                let mut hsm_guard = hsm
                    .lock()
                    .map_err(|_| BackendError::Internal("HSM provider lock".into()))?;
                hsm_guard
                    .provision(envelope)
                    .map_err(|e| BackendError::Internal(format!("HSM provision: {e}")))?;

                // After provisioning, load the public trust anchors and
                // wire an HSM-backed CEK unwrapper. Device decryption
                // key bytes never leave the HSM — `HsmKeyUnwrap` calls
                // `HsmProvider::unwrap_cek_*` for each decryption.
                match hsm_guard.get_public_key(hsm::KeyRole::SoftwareAuthority) {
                    Ok(sw_key) => {
                        let ka = hsm_guard.get_public_key(hsm::KeyRole::KeyAuthority).ok();
                        drop(hsm_guard);
                        let unwrap: std::sync::Arc<
                            dyn sumo_onboard::decryptor::KeyUnwrap + Send + Sync,
                        > = std::sync::Arc::new(hsm::HsmKeyUnwrap::new(
                            hsm.clone(),
                            "device-decrypt",
                        ));
                        self.manifest_provider.update_keys(sw_key, Some(unwrap), ka);
                        tracing::info!(
                            "loaded sw-authority + key-authority; CEK unwrap routed through HSM"
                        );
                    }
                    Err(e) => {
                        tracing::warn!("HSM provisioned but failed to load sw-authority: {e}");
                    }
                }
            }

            // Update NV metadata (security_version, fw_version) via single-bank path
            let mut nv = self.nv_write()?;
            let _result =
                ota::install(&mut *nv, self.bank_set, &[], &meta, true).map_err(map_ota_error)?;

            let transfer_id = self.next_id();
            {
                let mut ft = self.flash_transfer.lock().unwrap();
                *ft = Some(FlashTransferState {
                    transfer_id: transfer_id.clone(),
                    package_id: package_id.to_string(),
                    state: FlashState::AwaitingActivation,
                    image_size: 0,
                    verify_baseline_boot_id: None,
                    streamed_files: Vec::new(),
                });
            }
            // No-op for HSM single-bank (no bank dir under
            // images_dir; the keystore lives separately) but kept
            // for uniformity — any future component with content
            // here gets signed automatically.
            let target_bank = self.determine_target_bank()?;
            // Seed unstreamed files from the active bank so the IVD
            // signature below covers a complete bank, not a partial
            // one. No-op for full updates / single-bank / factory.
            self.seed_target_from_active(target_bank)?;
            self.ivd_sign_staged_bank(target_bank)?;
            return Ok(transfer_id);
        }

        // Streaming path: image_data is empty but image was already written to disk
        let is_streamed = image_data.is_empty() && pre_sha256.is_some();
        let is_crl = image_data.is_empty() && pre_sha256.is_none();

        // The bank that install_precomputed / install just made active.
        // Captured here so the activator block below uses the
        // authoritative answer instead of re-deriving via
        // determine_target_bank() — which is racy on first-ever flash
        // (no `current` symlink yet → falls back to NV, which
        // install_precomputed has by then flipped, returning the WRONG
        // bank). For CRL (no install), stays None and the activator
        // block is skipped via `if !is_crl`.
        let mut installed_bank: Option<Bank> = None;
        if is_crl {
            // CRL / security-floor-only manifest — raise floor without flashing.
            let mut nv = self.nv_write()?;
            let active = *self.running_bank.lock().unwrap();
            if let Some(mut fw_meta) = nv.read_fw_meta(self.bank_set, active) {
                if meta.fw_secver > fw_meta.min_security_ver {
                    fw_meta.min_security_ver = meta.fw_secver;
                    nv.write_fw_meta(self.bank_set, active, &mut fw_meta)
                        .map_err(|e| BackendError::Internal(format!("NV write: {e}")))?;
                }
            }
        } else if is_streamed {
            // Streaming path — image already written to staged file, use pre-computed hash
            let mut nv = self.nv_write()?;
            let result = ota::install_precomputed(
                &mut *nv,
                self.bank_set,
                pre_sha256.unwrap(),
                pre_size.unwrap_or(0),
                &meta,
                self.config.single_bank,
            )
            .map_err(map_ota_error)?;

            // Payloads were already streamed directly into the target bank dir
            // at upload time. install_precomputed flipped NV — nothing else to
            // do here.
            tracing::info!(
                bank_set = ?self.bank_set,
                target_bank = ?result.target_bank,
                "OTA install committed (files already in bank dir)"
            );
            installed_bank = Some(result.target_bank);
        } else {
            // Buffered path — install from memory
            let mut nv = self.nv_write()?;
            let result = ota::install(
                &mut *nv,
                self.bank_set,
                &image_data,
                &meta,
                self.config.single_bank,
            )
            .map_err(map_ota_error)?;

            // Write firmware payload to bank directory
            if let Some(ref images_dir) = self.images_dir {
                let set_name = self.bank_spec.dir_name.as_str();
                let bank_dir_name = match result.target_bank {
                    Bank::A => "bank_a",
                    Bank::B => "bank_b",
                };
                let bank_dir = images_dir.join(set_name).join(bank_dir_name);
                let _ = std::fs::create_dir_all(&bank_dir);
                let image_path = bank_dir.join("rootfs.img");
                tracing::info!(
                    "writing {} bytes to {}",
                    image_data.len(),
                    image_path.display()
                );
                std::fs::write(&image_path, &image_data).map_err(|e| {
                    BackendError::Internal(format!(
                        "failed to write image to {}: {e}",
                        image_path.display()
                    ))
                })?;
            }
            installed_bank = Some(result.target_bank);
        }

        // Bank activation: if a bank_activator is configured, invoke it now.
        // Use installed_bank captured from install_precomputed / install
        // above — that's the authoritative answer. Re-deriving via
        // determine_target_bank() here would return the OLD (now-inactive)
        // bank on first-ever flash because NV has been flipped but the
        // `current` symlink doesn't exist yet to override. Activator runs
        // on the bank we just wrote payloads to; success flips the symlink
        // so the next flash's determine_target_bank() reads correctly.
        if !is_crl {
            if let (Some(ref activator), Some(ref images_dir)) =
                (&self.bank_activator, &self.images_dir)
            {
                let wrote_to = installed_bank.ok_or_else(|| {
                    BackendError::Internal("installed_bank unset — unreachable for !is_crl".into())
                })?;
                let bank_dir = images_dir
                    .join(self.bank_spec.dir_name.as_str())
                    .join(bank_dir_name(wrote_to));
                if let Err(e) = activator.activate(&bank_dir) {
                    tracing::error!(
                        bank_set = ?self.bank_set,
                        bank_dir = %bank_dir.display(),
                        error = %e,
                        "bank activation failed during install finalize — rolling back"
                    );
                    let mut nv = self.nv_write()?;
                    let _ = ota::rollback(&mut *nv, self.bank_set);
                    return Err(BackendError::Internal(format!(
                        "bank activation failed: {e}"
                    )));
                }
                self.flip_current_symlink(wrote_to);
                tracing::info!(
                    bank_set = ?self.bank_set,
                    bank_dir = %bank_dir.display(),
                    "bank activated during install finalize"
                );
            }
        }

        if !is_crl {
            let (transfer_id, target_bank) = {
                let mut ft = self.flash_transfer.lock().unwrap();
                let tb = self.determine_target_bank()?;
                if let Some(ref mut t) = *ft {
                    // Reuse existing transfer from streaming upload path
                    t.package_id = package_id.to_string();
                    t.state = FlashState::AwaitingActivation;
                    t.image_size = image_size;
                    (t.transfer_id.clone(), tb)
                } else {
                    // Buffered path — create new transfer
                    let id = self.next_id();
                    *ft = Some(FlashTransferState {
                        transfer_id: id.clone(),
                        package_id: package_id.to_string(),
                        state: FlashState::AwaitingActivation,
                        image_size,
                        verify_baseline_boot_id: None,
                        streamed_files: Vec::new(),
                    });
                    (id, tb)
                }
            };
            // Self-sign before returning. `ivd_sign_staged_bank`
            // no-ops when the bank dir is absent (e.g. HSM
            // single-bank components).
            // Seed unstreamed files from the active bank so the IVD
            // signature below covers a complete bank, not a partial
            // one. No-op for full updates / single-bank / factory.
            self.seed_target_from_active(target_bank)?;
            self.ivd_sign_staged_bank(target_bank)?;
            return Ok(transfer_id);
        }
        // CRL: no flash transfer state — floor already applied, nothing to poll/finalize/commit

        Ok(self.next_id())
    }

    async fn get_flash_status(&self, transfer_id: &str) -> BackendResult<FlashStatus> {
        let ft = self.flash_transfer.lock().unwrap();
        let t = ft
            .as_ref()
            .ok_or_else(|| BackendError::EntityNotFound(transfer_id.to_string()))?;

        Ok(FlashStatus {
            transfer_id: t.transfer_id.clone(),
            package_id: t.package_id.clone(),
            state: t.state,
            progress: Some(FlashProgress {
                bytes_transferred: t.image_size,
                bytes_total: t.image_size,
                blocks_transferred: 1,
                blocks_total: 1,
                percent: 100.0,
            }),
            error: None,
        })
    }

    async fn finalize_flash(&self) -> BackendResult<()> {
        // Process staged package (HSM keys, firmware OTA install)
        let package_id = {
            let ft = self.flash_transfer.lock().unwrap();
            ft.as_ref()
                .map(|t| t.package_id.clone())
                .unwrap_or_default()
        };

        if !package_id.is_empty() {
            let packages = self.packages.lock().unwrap();
            if let Some(p) = packages.get(&package_id) {
                let manifest_type = p.validated.manifest_type;
                let raw_envelope = p.validated.raw_envelope.clone();
                drop(packages);

                // HSM key provisioning
                if manifest_type == ManifestType::HsmKeys {
                    if let Some(envelope) = raw_envelope.as_deref() {
                        if let Some(ref hsm) = self.hsm_provider {
                            let mut hsm_guard = hsm
                                .lock()
                                .map_err(|_| BackendError::Internal("HSM lock".into()))?;
                            hsm_guard.provision(envelope).map_err(|e| {
                                BackendError::Internal(format!("HSM provision: {e}"))
                            })?;

                            // Restart the HSM service so it reloads with the
                            // freshly-written keystore. The daemon was already
                            // running (Component::start brought it up at boot)
                            // but holds the old/empty keystore in memory until
                            // re-spawned. Backend-agnostic — no-op for HSE.
                            match hsm_guard.stop_service() {
                                Ok(()) | Err(hsm::HsmError::NotRunning) => {}
                                Err(e) => tracing::warn!("stop HSM service post-provision: {e}"),
                            }
                            match hsm_guard.start_service() {
                                Ok(port) => {
                                    tracing::info!(port, "HSM service restarted post-provision")
                                }
                                Err(hsm::HsmError::AlreadyRunning) => {}
                                Err(e) => tracing::warn!("start HSM service post-provision: {e}"),
                            }

                            // Load keys from HSM into manifest provider.
                            // Public trust anchors come out as bytes;
                            // the device decryption key stays inside
                            // the HSM and is invoked via HsmKeyUnwrap.
                            let ka = hsm_guard.get_public_key(hsm::KeyRole::KeyAuthority).ok();
                            match hsm_guard.get_public_key(hsm::KeyRole::SoftwareAuthority) {
                                Ok(sw_key) => {
                                    drop(hsm_guard);
                                    let unwrap: std::sync::Arc<
                                        dyn sumo_onboard::decryptor::KeyUnwrap + Send + Sync,
                                    > = std::sync::Arc::new(hsm::HsmKeyUnwrap::new(
                                        hsm.clone(),
                                        "device-decrypt",
                                    ));
                                    self.manifest_provider.update_keys(sw_key, Some(unwrap), ka);
                                    tracing::info!(
                                        "HSM keys provisioned; CEK unwrap routed through HSM"
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "HSM provisioned but failed to load sw-authority: {e}"
                                    );
                                }
                            }
                        }
                    }
                }

                // Firmware OTA: run install (rename staged files, update NV)
                if manifest_type == ManifestType::Firmware {
                    // Staged files already written during payload uploads.
                    // OTA install (NV update + rename) happens here.
                    let (meta, sha, size) = {
                        let pkg = self.packages.lock().unwrap();
                        let p = pkg.get(&package_id);
                        (
                            p.map(|p| p.validated.image_meta.clone()),
                            p.and_then(|p| p.validated.image_sha256),
                            p.and_then(|p| p.validated.image_size).unwrap_or(0),
                        )
                    };
                    if let Some(meta) = meta {
                        let mut nv = self.nv_write()?;
                        if let Err(e) = crate::ota::install_precomputed(
                            &mut *nv,
                            self.bank_set,
                            sha.unwrap_or([0; 32]),
                            size,
                            &meta,
                            self.config.single_bank,
                        ) {
                            tracing::warn!(
                                bank_set = ?self.bank_set,
                                error = %e,
                                "install_precomputed failed during finalize (NV metadata not updated)"
                            );
                        }
                    }
                }
            }
        }

        // Bank activation: if a bank_activator is configured, invoke it now.
        // Read NV.active_bank directly — install_precomputed (above, when
        // it ran) just flipped it to the just-installed bank, which is
        // exactly the bank that has the payloads the activator needs.
        // determine_target_bank() would return the OTHER bank (active.other())
        // when no `current` symlink exists yet (first flash) — that's
        // empty and would make the activator fail with "firmware not found".
        // See 2c9d2d8 for the original fix to this race; d25d967 re-introduced
        // the determine_target_bank() call and reopened the bug for
        // first-ever-flash on activator-backed components.
        if let (Some(ref activator), Some(ref images_dir)) =
            (&self.bank_activator, &self.images_dir)
        {
            let wrote_to = {
                let nv = self
                    .nv
                    .lock()
                    .map_err(|_| BackendError::Internal("nv lock".into()))?;
                let state = nv
                    .read_boot_state()
                    .ok_or_else(|| BackendError::Internal("no boot state".into()))?;
                state.banks[self.bank_set.as_index()].active_bank
            };
            let bank_dir = images_dir
                .join(self.bank_spec.dir_name.as_str())
                .join(bank_dir_name(wrote_to));
            if let Err(e) = activator.activate(&bank_dir) {
                tracing::error!(
                    bank_set = ?self.bank_set,
                    bank_dir = %bank_dir.display(),
                    error = %e,
                    "bank activation failed during finalize — rolling back"
                );
                let mut nv = self.nv_write()?;
                let _ = ota::rollback(&mut *nv, self.bank_set);
                return Err(BackendError::Internal(format!(
                    "bank activation failed: {e}"
                )));
            }
            self.flip_current_symlink(wrote_to);
            tracing::info!(
                bank_set = ?self.bank_set,
                bank_dir = %bank_dir.display(),
                "bank activated during finalize"
            );
        }

        let mut ft = self.flash_transfer.lock().unwrap();
        if let Some(ref mut t) = *ft {
            // Single-bank components (HSM): finalize *writes* the new keys
            // immediately to the live store. There's no reboot trial — the
            // new state is in effect now. Skip AwaitingReboot and report
            // Activated directly so the orchestrator/viewer don't see a
            // theatrical "awaiting reboot" step that never happens.
            //
            // Dual-bank (boot, hypervisor, vm1, vm2): finalize flips the
            // next-boot bank pointer; new code starts running after the
            // orchestrator-driven `ecu_reset`.
            t.state = if self.config.single_bank {
                FlashState::Activated
            } else {
                FlashState::AwaitingReboot
            };
        }
        Ok(())
    }

    async fn validate(&self) -> BackendResult<()> {
        // Idempotent re-validation. Accepts either pre-finalize
        // (AwaitingActivation) or post-finalize (AwaitingReboot, dual-bank)
        // — the latter lets the orchestrator down-shift to Validated for
        // re-verification across power cycles before committing to reset.
        // Already in Validated is a no-op.
        //
        // Today this is a state-only transition; a follow-up will re-read
        // the inactive bank and re-verify the SUIT signature + image hash.
        let mut ft = self.flash_transfer.lock().unwrap();
        let transfer = ft
            .as_mut()
            .ok_or_else(|| BackendError::EntityNotFound("No flash transfer in progress".into()))?;
        match transfer.state {
            FlashState::AwaitingActivation | FlashState::Validated | FlashState::AwaitingReboot => {
                transfer.state = FlashState::Validated;
                Ok(())
            }
            other => Err(BackendError::InvalidRequest(format!(
                "validate() requires AwaitingActivation, Validated, or AwaitingReboot, got {:?}",
                other
            ))),
        }
    }

    async fn invalidate(&self) -> BackendResult<()> {
        // Demote a previously-validated transfer back to AwaitingActivation —
        // the orchestrator should re-call validate() before proceeding. Used
        // when the bank can't be hardware-sealed and a power cycle could
        // have introduced drift.
        let mut ft = self.flash_transfer.lock().unwrap();
        let transfer = ft
            .as_mut()
            .ok_or_else(|| BackendError::EntityNotFound("No flash transfer in progress".into()))?;
        match transfer.state {
            FlashState::Validated => {
                transfer.state = FlashState::AwaitingActivation;
                Ok(())
            }
            other => Err(BackendError::InvalidRequest(format!(
                "invalidate() requires Validated, got {:?}",
                other
            ))),
        }
    }

    async fn activate(&self) -> BackendResult<()> {
        // Schedule activation. For dual-bank components the activation
        // event is the reboot — we move to AwaitingReboot and the
        // orchestrator must call ecu_reset() to complete. For single-bank
        // components (HSM, config) the artifact write itself was the
        // activation event during finalize, so we go straight to
        // Activated; the orchestrator should then commit_flash() to
        // reach the Complete terminal.
        let mut ft = self.flash_transfer.lock().unwrap();
        let transfer = ft
            .as_mut()
            .ok_or_else(|| BackendError::EntityNotFound("No flash transfer in progress".into()))?;
        match transfer.state {
            FlashState::Validated => {
                transfer.state = if self.config.single_bank {
                    FlashState::Activated
                } else {
                    FlashState::AwaitingReboot
                };
                Ok(())
            }
            other => Err(BackendError::InvalidRequest(format!(
                "activate() requires Validated, got {:?}",
                other
            ))),
        }
    }

    async fn ecu_reset(&self, _reset_type: u8) -> BackendResult<Option<u8>> {
        // VM "reset" — simulate reboot:
        // 1. Switch running_bank to NV active_bank (the bank install() staged)
        // 2. Increment boot_count for trial mode (like process_boot())
        // 3. Advance flash state to Activated
        // 4. Reset session and security (ISO 14229)

        if !self.config.single_bank {
            let idx = self.bank_set.as_index();
            let mut nv = self.nv_write()?;
            if let Some(mut state) = nv.read_boot_state() {
                // Switch to the staged bank
                *self.running_bank.lock().unwrap() = state.banks[idx].active_bank;

                // Simulate process_boot(): increment boot_count in trial mode
                if !state.banks[idx].committed {
                    state.banks[idx].boot_count += 1;
                    let _ = nv.write_boot_state(&mut state);
                }
            }
        }
        // Single-bank components: no bank switch, always bank A, always committed

        // For dual-bank components, snapshot the live boot_id before the
        // VM restarts. Promotion out of Verifying needs a baseline to
        // distinguish "the previous fw is still publishing" from "the new
        // fw is now reporting" — the new fw boots with a freshly generated
        // boot_id (random per guest lifetime), so a *different* boot_id is
        // definitive proof we're reading post-reset data. hb_seq alone
        // can't tell us: qvm-shmem regions persist across guest lifetimes
        // and the new daemon's seq counter is observed continuing from
        // whatever the previous lifetime left there.
        //
        // Capture the boot_id whenever ANY heartbeat is present, regardless
        // of guest_state. Previously this gated on `guest_state == 1` which
        // caused a real bug: if the guest happened to be in Booting /
        // Degraded / ShuttingDown / momentarily-stale at probe time, the
        // baseline was discarded → guest_is_running then accepted any
        // running heartbeat → Activated declared 45ms after the new qvm
        // spawn, reading the previous lifetime's stale shmem.
        //
        // For factory-provision (truly never-started VM) shmem has no
        // valid heartbeat → query_vm_health returns None → baseline
        // remains None → guest_is_running fallback accepts any running
        // heartbeat. That path is preserved.
        let baseline_boot_id = if self.config.single_bank {
            None
        } else {
            let health = match self.vm_service_addr.as_ref() {
                Some(sock) => query_vm_health(sock, &self.entity_info.id).await,
                None => None,
            };
            let baseline = health.map(|h| h.boot_id);
            tracing::info!(
                component = %self.entity_info.id,
                baseline_boot_id = ?baseline,
                "captured baseline boot_id for activation check"
            );
            baseline
        };

        // Advance flash state.
        //
        // Single-bank (HSM): no reboot, no trial — already Activated since
        // finalize_flash, leave it.
        //
        // Dual-bank (VM, hypervisor): the bank flip starts the new
        // firmware coming up. Move to Verifying; get_activation_state
        // will lazily promote to Activated once the component-specific
        // health check (vm-service guest health for VMs) reports ready.
        {
            let mut ft = self.flash_transfer.lock().unwrap();
            if let Some(ref mut t) = *ft {
                if self.config.single_bank || self.bank_set == BankSet::HostOs {
                    // Single-bank (HSM) and host-os: no guest health to verify
                    t.state = FlashState::Activated;
                } else {
                    t.state = FlashState::Verifying;
                    t.verify_baseline_boot_id = baseline_boot_id;
                }
            }
        }

        // Reset session and security (ISO 14229)
        *self.session.lock().unwrap() = SessionState::Default;
        *self.security.lock().unwrap() = SecurityAccessState::default();

        // Bank activation happens at install-finalize (finalize_flash),
        // not here. ecu_reset just transitions the flash state machine.

        // Pick "restart" vs "start" based on whether the guest was actually
        // running pre-reset. The baseline_hb_seq probe above already told us
        // (Some = guest_state==1 = running). For an offline guest (factory
        // provision, post-crash) the shutdown step is a phantom — vm-service
        // would handle it (NotRunning → fall through to start_vm) but the
        // orchestrator-/GUI-visible intent should be "start", not "restart",
        // so the cluster tile doesn't display "Shutting Down" for a guest
        // that never ran.
        let action = if baseline_boot_id.is_some() {
            "restart"
        } else {
            "start"
        };

        // Flip the `current` symlink so vm-service boots the right bank
        if let (Some(ref images_dir), Some(ref socket_path)) =
            (&self.images_dir, &self.vm_service_addr)
        {
            let set_name = self.bank_spec.dir_name.as_str();
            let target_bank = *self.running_bank.lock().unwrap();
            let bank_dir_name = match target_bank {
                Bank::A => "bank_a",
                Bank::B => "bank_b",
            };
            let symlink_path = images_dir.join(set_name).join("current");
            // Relative target — symlink is a sibling of bank_a/bank_b.
            let target = Path::new(bank_dir_name);
            // Atomic symlink swap: create temp, rename over existing
            let tmp_link = symlink_path.with_extension("tmp");
            let _ = std::fs::remove_file(&tmp_link);
            if let Err(e) = std::os::unix::fs::symlink(target, &tmp_link)
                .and_then(|()| std::fs::rename(&tmp_link, &symlink_path))
            {
                tracing::warn!("failed to flip current symlink for {set_name}: {e}");
            } else {
                tracing::info!("flipped {set_name}/current -> {bank_dir_name}");
            }

            let id = &self.entity_info.id;
            match Self::notify_vm_service(socket_path, id, action).await {
                Ok(()) => tracing::info!("vm-service {action} requested for {id}"),
                Err(e) => tracing::warn!("failed to notify vm-service for {id}: {e}"),
            }
        } else if let Some(ref socket_path) = self.vm_service_addr {
            // No images_dir — just notify without symlink flip
            let id = &self.entity_info.id;
            match Self::notify_vm_service(socket_path, id, action).await {
                Ok(()) => tracing::info!("vm-service {action} requested for {id}"),
                Err(e) => tracing::warn!("failed to notify vm-service for {id}: {e}"),
            }
        }

        Ok(None)
    }

    async fn list_flash_transfers(&self) -> BackendResult<Vec<FlashStatus>> {
        let ft = self.flash_transfer.lock().unwrap();
        match ft.as_ref() {
            Some(t) => Ok(vec![FlashStatus {
                transfer_id: t.transfer_id.clone(),
                package_id: t.package_id.clone(),
                state: t.state,
                progress: Some(FlashProgress {
                    bytes_transferred: t.image_size,
                    bytes_total: t.image_size,
                    blocks_transferred: 1,
                    blocks_total: 1,
                    percent: 100.0,
                }),
                error: None,
            }]),
            None => Ok(vec![]),
        }
    }

    async fn get_activation_state(&self) -> BackendResult<ActivationState> {
        // Check upload phase first (streaming firmware download in progress)
        let upload_state = *self.upload_phase.lock().unwrap();

        // If we're in Verifying, ask the component's health source whether
        // it's now ready. Promote to Activated lazily on poll so the
        // orchestrator just sees the state advance — no background task,
        // no out-of-band signal.
        if matches!(*self.flash_transfer.lock().unwrap(),
            Some(ref t) if t.state == FlashState::Verifying)
            && self.guest_is_running().await
        {
            let mut ft = self.flash_transfer.lock().unwrap();
            if let Some(ref mut t) = *ft {
                if t.state == FlashState::Verifying {
                    t.state = FlashState::Activated;
                    tracing::info!(
                        component = %self.entity_info.id,
                        "verifying → activated (guest health ok)"
                    );
                }
            }
        }

        let flash_state = {
            let ft = self.flash_transfer.lock().unwrap();
            ft.as_ref().map(|t| t.state)
        };

        let nv = self
            .nv
            .lock()
            .map_err(|_| BackendError::Internal("lock".into()))?;
        let status = ota::status(&*nv, self.bank_set)
            .ok_or_else(|| BackendError::Internal("no boot state".into()))?;

        // Use running_bank for versions (not NV active_bank which may be staged)
        let rb = *self.running_bank.lock().unwrap();
        let active_meta = nv.read_fw_meta(self.bank_set, rb);
        let previous_meta = nv.read_fw_meta(self.bank_set, rb.other());

        // Priority: upload phase > flash transfer > NV state.
        // A component with no fw_meta on either bank has never been
        // OTA-written — report Initial regardless of the committed flag
        // (defends against stale NV layouts that may show !committed for
        // never-touched slots).
        let state = match upload_state {
            Some(s) => s, // Transferring during firmware download
            None => match flash_state {
                Some(s) => s,
                None if active_meta.is_none() && previous_meta.is_none() => FlashState::Initial,
                None if !status.committed => FlashState::Activated, // trial without transfer (e.g. after restart)
                None => FlashState::Complete,                       // idle — no active update
            },
        };

        // Version strings now come from each bank's signed IVD manifest
        // identity (F189), not NvFwMeta. Present a version only when the
        // bank both has FW meta (has been written) AND a verifiable
        // manifest carrying a non-empty version.
        let version_of = |bank: Bank| -> Option<String> {
            self.verified_bank_identity(bank)
                .map(|id| id.version)
                .filter(|v| !v.is_empty())
        };
        let active_version = active_meta.as_ref().and_then(|_| version_of(rb));
        let previous_version = previous_meta.as_ref().and_then(|_| version_of(rb.other()));

        Ok(ActivationState {
            supports_rollback: self.config.supports_rollback,
            state,
            active_version,
            previous_version,
            // Surface the activator's declared reset kind on the wire so the
            // orchestrator can route restarts correctly (Phase 2 of
            // tasks/reset-kind-and-status-restart.md). Default Local when no
            // activator is configured.
            reset_kind: self.reset_kind(),
        })
    }

    async fn commit_flash(&self) -> BackendResult<()> {
        let mut nv = self.nv_write()?;
        match ota::commit(&mut *nv, self.bank_set) {
            Ok(()) => {}
            Err(ota::OtaError::AlreadyCommitted) => {} // CRL or idempotent commit — OK
            Err(e) => return Err(map_ota_error(e)),
        }
        // Drop the NV write lock before acquiring the HSM mutex —
        // arm_enrollment may itself touch on-disk state.
        drop(nv);

        // Arm in-band enrolment for this VM's principal. The guest
        // will boot the just-promoted bank, connect to vhsm-ssd,
        // and run HELLO → ENROLL_ASSISTED; the daemon resolves
        // identity by source IP and consumes this pending flag.
        // Non-VM banks (e.g. host-os, hsm) skip — enrol is a
        // vm-principal concept.
        if matches!(self.bank_set, BankSet::Vm1 | BankSet::Vm2) {
            if let Some(ref hsm) = self.hsm_provider {
                let mut guard = hsm
                    .lock()
                    .map_err(|_| BackendError::Internal("hsm provider mutex poisoned".into()))?;
                // ttl=None: operator-managed lifecycle. Pending stays
                // until consumed; re-installs simply re-arm.
                if let Err(e) = guard.arm_enrollment(&self.entity_info.id, None) {
                    // Non-fatal — operator can re-arm manually, or the
                    // existing cert (if any) lets the guest keep
                    // working. Trial-boot rollback also handles the
                    // "new bank can't enrol" case.
                    tracing::warn!(
                        vm_id = %self.entity_info.id,
                        error = %e,
                        "arm_enrollment after commit failed; guest may need manual arm"
                    );
                } else {
                    tracing::info!(
                        vm_id = %self.entity_info.id,
                        "armed ENROLL_ASSISTED after commit_flash"
                    );
                }
            }
        }

        // Clear flash transfer state
        *self.flash_transfer.lock().unwrap() = None;
        Ok(())
    }

    async fn rollback_flash(&self) -> BackendResult<()> {
        if !self.config.supports_rollback {
            return Err(BackendError::InvalidRequest(
                "rollback not supported for this component".into(),
            ));
        }
        let mut nv = self.nv_write()?;
        ota::rollback(&mut *nv, self.bank_set).map_err(map_ota_error)?;
        // Clear flash transfer state after rollback
        *self.flash_transfer.lock().unwrap() = None;
        Ok(())
    }

    // --- Session ---

    async fn get_session_mode(&self) -> BackendResult<SessionMode> {
        let session = self.session.lock().unwrap();
        let (name, id) = match *session {
            SessionState::Default => ("default", 0x01),
            SessionState::Programming => ("programming", 0x02),
        };
        Ok(SessionMode {
            mode: "session".to_string(),
            session: name.to_string(),
            session_id: id,
        })
    }

    async fn set_session_mode(&self, session: &str) -> BackendResult<SessionMode> {
        let new_state = match session.to_lowercase().as_str() {
            "default" => SessionState::Default,
            "programming" => SessionState::Programming,
            _ => {
                return Err(BackendError::InvalidRequest(format!(
                    "unknown session: {session}"
                )))
            }
        };

        {
            let mut s = self.session.lock().unwrap();
            let changed = *s != new_state;
            *s = new_state;
            if changed {
                // Security resets on session change (ISO 14229)
                let mut sec = self.security.lock().unwrap();
                *sec = SecurityAccessState::default();
            }
        }

        self.get_session_mode().await
    }

    // --- Security ---

    async fn get_security_mode(&self) -> BackendResult<SecurityMode> {
        let sec = self.security.lock().unwrap();
        let (state, level, seed) = match sec.phase {
            SecurityPhase::Locked => (SecurityState::Locked, None, None),
            SecurityPhase::SeedAvailable => {
                let seed_hex = sec
                    .pending_seed
                    .as_ref()
                    .map(|s| s.iter().map(|b| format!("{b:02x}")).collect::<String>());
                (SecurityState::SeedAvailable, Some(sec.level), seed_hex)
            }
            SecurityPhase::Unlocked => (SecurityState::Unlocked, Some(sec.level), None),
        };
        Ok(SecurityMode {
            mode: "security".to_string(),
            state,
            level,
            available_levels: Some(vec![1]),
            seed,
        })
    }

    async fn set_security_mode(
        &self,
        value: &str,
        key: Option<&[u8]>,
    ) -> BackendResult<SecurityMode> {
        let value_lower = value.to_lowercase();

        if value_lower.ends_with("_requestseed") {
            let level_str = value_lower.trim_end_matches("_requestseed");
            let level = parse_security_level(level_str)?;

            let seed = self.security_provider.generate_seed(self.bank_set, level);
            {
                let mut sec = self.security.lock().unwrap();
                sec.phase = SecurityPhase::SeedAvailable;
                sec.level = level;
                sec.pending_seed = Some(seed);
            }

            self.get_security_mode().await
        } else {
            let level = parse_security_level(&value_lower)?;
            let key_bytes = key.ok_or_else(|| {
                BackendError::InvalidRequest("missing key — required when sending key".into())
            })?;

            let pending_seed = {
                let sec = self.security.lock().unwrap();
                if sec.phase != SecurityPhase::SeedAvailable || sec.level != level {
                    return Err(BackendError::InvalidRequest(
                        "no pending seed — call requestseed first".into(),
                    ));
                }
                sec.pending_seed
                    .clone()
                    .ok_or_else(|| BackendError::Internal("seed state inconsistency".into()))?
            };

            if !self
                .security_provider
                .validate_key(self.bank_set, level, &pending_seed, key_bytes)
            {
                let mut sec = self.security.lock().unwrap();
                sec.phase = SecurityPhase::Locked;
                sec.pending_seed = None;
                return Err(BackendError::SecurityRequired(level));
            }

            {
                let mut sec = self.security.lock().unwrap();
                sec.phase = SecurityPhase::Unlocked;
                sec.pending_seed = None;
            }

            self.get_security_mode().await
        }
    }
}

// ---------------------------------------------------------------------------
// DID helpers (adapted from old models.rs)
// ---------------------------------------------------------------------------

pub(crate) struct DidEntry {
    pub(crate) id: &'static str,
    pub(crate) did: u16,
    pub(crate) name: &'static str,
    pub(crate) data_type: &'static str,
    pub(crate) writable: bool,
}

pub(crate) static DID_REGISTRY: &[DidEntry] = &[
    DidEntry {
        id: "spare_part_number",
        did: did::DID_SPARE_PART_NUMBER,
        name: "Spare Part Number",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "ecu_sw_number",
        did: did::DID_ECU_SW_NUMBER,
        name: "ECU Software Number",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "fw_version",
        did: did::DID_FW_VERSION,
        name: "Firmware Version",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "supplier_id",
        did: did::DID_SUPPLIER_ID,
        name: "Supplier ID",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "manufacturing_date",
        did: did::DID_MANUFACTURING_DATE,
        name: "Manufacturing Date",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "serial_number",
        did: did::DID_SERIAL_NUMBER,
        name: "Serial Number",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "vin",
        did: did::DID_VIN,
        name: "VIN",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "ecu_hw_number",
        did: did::DID_ECU_HW_NUMBER,
        name: "ECU Hardware Number",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "supplier_hw_number",
        did: did::DID_SUPPLIER_HW_NUMBER,
        name: "Supplier HW Number",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "supplier_hw_version",
        did: did::DID_SUPPLIER_HW_VERSION,
        name: "Supplier HW Version",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "supplier_sw_number",
        did: did::DID_SUPPLIER_SW_NUMBER,
        name: "Supplier SW Number",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "supplier_sw_version",
        did: did::DID_SUPPLIER_SW_VERSION,
        name: "Supplier SW Version",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "system_name",
        did: did::DID_SYSTEM_NAME,
        name: "System Name",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "tester_serial",
        did: did::DID_TESTER_SERIAL,
        name: "Tester Serial",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "programming_date",
        did: did::DID_PROGRAMMING_DATE,
        name: "Programming Date",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "odx_file_id",
        did: did::DID_ODX_FILE_ID,
        name: "ODX File ID",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "active_bank",
        did: did::DID_ACTIVE_BANK,
        name: "Active Bank",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "committed",
        did: did::DID_COMMITTED,
        name: "Committed",
        data_type: "bool",
        writable: false,
    },
    DidEntry {
        id: "min_security_ver",
        did: did::DID_MIN_SECURITY_VER,
        name: "Min Security Version",
        data_type: "uint32",
        writable: false,
    },
    DidEntry {
        id: "current_security_ver",
        did: did::DID_CURRENT_SECURITY_VER,
        name: "Current Security Version",
        data_type: "uint32",
        writable: false,
    },
    DidEntry {
        id: "boot_count",
        did: did::DID_BOOT_COUNT,
        name: "Boot Count",
        data_type: "uint8",
        writable: false,
    },
    DidEntry {
        id: "guest_state",
        did: did::DID_GUEST_STATE,
        name: "Guest State",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "heartbeat_seq",
        did: did::DID_HEARTBEAT_SEQ,
        name: "Heartbeat Seq",
        data_type: "uint32",
        writable: false,
    },
];

pub(crate) fn resolve_param(param_id: &str) -> Option<(u16, Option<&'static DidEntry>)> {
    if let Some(entry) = DID_REGISTRY.iter().find(|d| d.id == param_id) {
        return Some((entry.did, Some(entry)));
    }
    let hex_str = param_id
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .trim_start_matches("runtime_");
    if let Ok(did) = u16::from_str_radix(hex_str, 16) {
        let reg = DID_REGISTRY.iter().find(|d| d.did == did);
        return Some((did, reg));
    }
    None
}

pub(crate) fn did_value_to_json(
    _did_num: u16,
    value: &[u8],
    reg: Option<&DidEntry>,
) -> serde_json::Value {
    let data_type = reg.map(|r| r.data_type).unwrap_or("bytes");
    match data_type {
        "bool" => serde_json::Value::Bool(value.first().copied().unwrap_or(0) != 0),
        "uint8" => serde_json::json!(value.first().copied().unwrap_or(0)),
        "uint32" => {
            let v = if value.len() >= 4 {
                u32::from_le_bytes([value[0], value[1], value[2], value[3]])
            } else {
                0
            };
            serde_json::json!(v)
        }
        "string" => {
            let s = VmBackend::<nv_store::block::MemBlockDevice>::nv_bytes_to_string(value);
            serde_json::Value::String(s)
        }
        _ => {
            let end = value.iter().position(|&c| c == 0).unwrap_or(value.len());
            if let Ok(s) = std::str::from_utf8(&value[..end]) {
                if !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                    return serde_json::Value::String(s.to_string());
                }
            }
            let hex: String = value.iter().map(|b| format!("{b:02x}")).collect();
            serde_json::Value::String(format!("0x{hex}"))
        }
    }
}

pub(crate) fn bank_dir_name(bank: Bank) -> &'static str {
    match bank {
        Bank::A => "bank_a",
        Bank::B => "bank_b",
    }
}

/// Convert a manifest [`IvdIdentity`] into the `(did, bytes)` pairs for
/// the 9 SW-identity DIDs, each rendered in the historical fixed-width
/// UDS byte form (UTF-8, NUL-padded / truncated to the width that DID
/// used when it lived in NvFwMeta — 32 bytes, except programming_date's
/// 8). Empty identity strings are skipped (DID stays not-found), so a
/// blank manifest identity behaves like an unprovisioned field.
fn identity_to_did_bytes(identity: &hsm::ivd::IvdIdentity) -> Vec<(u16, Vec<u8>)> {
    /// Pad/truncate a UTF-8 string to `width` bytes, NUL-padded — the
    /// same fixed-width form `read_did` used to return from NvFwMeta.
    fn fixed(s: &str, width: usize) -> Vec<u8> {
        let mut buf = vec![0u8; width];
        let n = s.len().min(width);
        buf[..n].copy_from_slice(&s.as_bytes()[..n]);
        buf
    }

    // (did, value, field-width). `version` → F189, `system_name` → F197.
    let fields: [(u16, &str, usize); 9] = [
        (did::DID_FW_VERSION, &identity.version, 32),
        (did::DID_ECU_SW_NUMBER, &identity.ecu_sw_number, 32),
        (
            did::DID_SUPPLIER_SW_NUMBER,
            &identity.supplier_sw_number,
            32,
        ),
        (
            did::DID_SUPPLIER_SW_VERSION,
            &identity.supplier_sw_version,
            32,
        ),
        (did::DID_SPARE_PART_NUMBER, &identity.spare_part_number, 32),
        (did::DID_ODX_FILE_ID, &identity.odx_file_id, 32),
        (did::DID_SYSTEM_NAME, &identity.system_name, 32),
        (did::DID_PROGRAMMING_DATE, &identity.programming_date, 8),
        (did::DID_TESTER_SERIAL, &identity.tester_serial, 32),
    ];
    fields
        .iter()
        .filter(|(_, s, _)| !s.is_empty())
        .map(|&(did, s, width)| (did, fixed(s, width)))
        .collect()
}

/// Render a verified IVD manifest as the `x-sumo-installed-manifest`
/// JSON body: the signed identity + per-file `(path, sha256-hex)`
/// inventory + the base64 of the raw signature and manifest bytes (so a
/// SW-mapping tool can re-verify the device signature independently).
fn installed_manifest_json(vm: &hsm::ivd::VerifiedManifest) -> serde_json::Value {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let m = &vm.manifest;
    let id = &m.identity;

    let files: Vec<serde_json::Value> = m
        .files
        .iter()
        .map(|f| {
            serde_json::json!({
                "path": f.relative_path,
                "sha256": hex::encode(&f.sha256),
            })
        })
        .collect();

    serde_json::json!({
        "ivd_version": m.ivd_version,
        "gen": m.gen,
        "signed_at_unix": m.signed_at_unix,
        "identity": {
            "name": id.name,
            "version": id.version,
            "ecu_sw_number": id.ecu_sw_number,
            "supplier_sw_number": id.supplier_sw_number,
            "supplier_sw_version": id.supplier_sw_version,
            "spare_part_number": id.spare_part_number,
            "odx_file_id": id.odx_file_id,
            "system_name": id.system_name,
            "programming_date": id.programming_date,
            "tester_serial": id.tester_serial,
        },
        "files": files,
        "signature_b64": b64.encode(&vm.signature),
        "manifest_b64": b64.encode(&vm.manifest_bytes),
    })
}

/// `true` if `bank_dir` has no files that IVD signing would attest to.
/// Skips IVD's own outputs (manifest + signature) so a re-sign doesn't
/// trip on a previous run's artefacts.
fn bank_dir_is_payload_empty(bank_dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(bank_dir) else {
        return true;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if name == hsm::ivd::IVD_MANIFEST_FILE || name == hsm::ivd::IVD_SIGNATURE_FILE {
            continue;
        }
        return false;
    }
    true
}
// `bank_set_dir_name` / `bank_file_names` / `payload_target_name`
// retired in Phase 2 — per-slot behavior lives on `BankSetSpec` in
// `crate::bank_spec` now and is read off `self.bank_spec` for the
// backend or passed as `&BankSetSpec` to free functions in
// `streaming::process_envelope_stream`.

fn map_ota_error(e: ota::OtaError) -> BackendError {
    match e {
        ota::OtaError::InTrial => BackendError::Busy("bank set is in trial mode".into()),
        ota::OtaError::AlreadyCommitted => BackendError::Busy("already committed".into()),
        ota::OtaError::NotInTrial => BackendError::Busy("not in trial mode".into()),
        ota::OtaError::SecurityVersionTooLow { image, floor } => BackendError::InvalidRequest(
            format!("security version {image} below anti-rollback floor {floor}"),
        ),
        other => BackendError::Internal(format!("{other}")),
    }
}

// ---------------------------------------------------------------------------
// Guest health (via vm-service HTTP API)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct GuestHealth {
    pub guest_state: u32,
    pub hb_seq: u32,
    /// Random per-guest-lifetime id from the heartbeat wire format. Used
    /// by `guest_is_running` to confirm we're reading data from the
    /// post-reset lifetime, not stale shmem data from the previous one
    /// (qvm-shmem regions persist across stop/start).
    pub boot_id: u32,
    /// Coarse health status string ("running" / "stopped" / "unhealthy").
    /// VmBackend treats anything not "running" as not-yet-activated —
    /// captures the stale-heartbeat case (vm-service flips to
    /// "unhealthy" after 5s of stuck seq) without duplicating that
    /// timeout here.
    pub status: String,
}

/// Synthesise a [`GuestHealth`] snapshot for a component that has no
/// vm-service backing (e.g. activator-backed components like RT/M7).
/// Called from `VmBackend::read_data` when `vm_service_addr` is None.
///
/// Implementations should be cheap (the call lands on the SOVD read-data
/// hot path served by the campaign viewer). Internal caching is fine
/// when the underlying source is expensive (`m7loader -q` shells out).
pub trait HealthProbe: Send + Sync {
    fn probe(&self) -> Option<GuestHealth>;
}

/// Query vm-service health endpoint via TCP loopback.
/// Returns guest_state and hb_seq from the JSON response.
/// Query vm-service's `/vms/<name>/health` endpoint over TCP loopback.
///
/// **Async** intentionally: `vm-mgr` runs on the same tokio runtime as
/// vm-service (supernova embeds both). A blocking `std::net::TcpStream`
/// call inside an `async fn` parks an entire tokio worker for up to the
/// 2-second read timeout, which is observable as "every other SOVD DID
/// read takes 2s" when workers are scarce (e.g. the 2-core S32G3).
/// Using `tokio::net::TcpStream` keeps the worker available — the await
/// suspension lets other futures run while we wait on I/O.
async fn query_vm_health(addr: &str, vm_name: &str) -> Option<GuestHealth> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    // Cap connect+read at 2 s combined. Both ends are on loopback so a
    // healthy vm-service responds in microseconds; this timeout is a
    // ceiling on misbehaviour.
    let deadline = std::time::Duration::from_secs(2);

    let mut stream = tokio::time::timeout(deadline, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let request = format!(
        "GET /vms/{vm_name}/health HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n"
    );
    tokio::time::timeout(deadline, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;

    let mut buf = Vec::with_capacity(1024);
    tokio::time::timeout(deadline, stream.read_to_end(&mut buf))
        .await
        .ok()?
        .ok()?;
    let response = std::str::from_utf8(&buf).ok()?;

    let body = response.split("\r\n\r\n").nth(1)?;
    let json: serde_json::Value = serde_json::from_str(body).ok()?;

    let guest_state = json.get("guest_state")?.as_u64()? as u32;
    let hb_seq = json.get("hb_seq")?.as_u64()? as u32;
    let boot_id = json.get("boot_id")?.as_u64()? as u32;
    let status = json
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Some(GuestHealth {
        guest_state,
        hb_seq,
        boot_id,
        status,
    })
}

fn guest_state_str(state: u32) -> &'static str {
    match state {
        0 => "booting",
        1 => "running",
        2 => "degraded",
        3 => "shutting_down",
        _ => "unknown",
    }
}

fn parse_security_level(s: &str) -> BackendResult<u8> {
    let digits = s.trim_start_matches("level");
    digits
        .parse::<u8>()
        .map_err(|_| BackendError::InvalidRequest(format!("invalid security level: {s}")))
}

// ---------------------------------------------------------------------------
// Single-source SW identity: end-to-end tests proving the F187-F19E
// identification DIDs are served from the signed IVD manifest (not NV),
// the cache invalidates, and a tampered manifest is refused.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod identity_tests {
    use super::*;
    use crate::manifest_provider::ManifestError;
    use crate::ota::ImageMeta;
    use hsm::sim::SimHsm;
    use hsm::HsmProvider;
    use nv_store::block::MemBlockDevice;
    use nv_store::store::MIN_NV_DEVICE_SIZE;

    /// Manifest provider stub — the identity path never validates a SUIT
    /// envelope (the package is injected directly), so this can be inert.
    struct NoopManifest;
    impl ManifestProvider for NoopManifest {
        fn validate(&self, _d: &[u8], _m: u32) -> Result<ValidatedFirmware, ManifestError> {
            Err(ManifestError::ParseError("unused in identity tests".into()))
        }
    }
    struct NoopSecurity;
    impl SecurityProvider for NoopSecurity {
        fn generate_seed(&self, _component: BankSet, _level: u8) -> Vec<u8> {
            Vec::new()
        }
        fn validate_key(&self, _component: BankSet, _level: u8, _seed: &[u8], _key: &[u8]) -> bool {
            true
        }
    }

    /// Build a fully-provisioned SimHsm: keystore manifest present (so
    /// `is_provisioned()` is true) plus the device `ivd-signing` keypair
    /// (so `sign`/`verify` work). Mirrors `hsm::ivd` test setup.
    fn provisioned_hsm(tag: &str) -> (Arc<Mutex<dyn hsm::HsmProvider>>, PathBuf) {
        use hsm::payload::*;
        let keystore = std::env::temp_dir().join(format!("vm-mgr-identity-ks-{tag}"));
        let _ = std::fs::remove_dir_all(&keystore);
        std::fs::create_dir_all(&keystore).unwrap();

        let hsm = SimHsm::new(PathBuf::from("/dev/null"), keystore.clone(), 5400);
        let ks = HsmKeystore {
            schema_version: SCHEMA_VERSION,
            security_version: 1,
            identities: vec![],
            slots: vec![KeySlot {
                key_id: hsm::ivd::IVD_KEY_ID.to_string(),
                key_kind: KEY_TYPE_EC_P256,
                anchor_public_key: None,
                allowed_guests: None,
                allowed_ops: Some(vec![OP_SIGN, OP_VERIFY, OP_GET_PUBKEY]),
            }],
        };
        hsm.write_keystore(&ks).unwrap();
        hsm.ensure_device_keys().unwrap();
        std::fs::write(keystore.join("provision_state"), b"1\n").unwrap();
        assert!(hsm.is_provisioned().unwrap());

        (Arc::new(Mutex::new(hsm)), keystore)
    }

    fn sample_image_meta() -> ImageMeta {
        let mut m = ImageMeta::default();
        let set = |dst: &mut [u8], s: &[u8]| dst[..s.len()].copy_from_slice(s);
        set(&mut m.fw_version, b"1.2.0");
        set(&mut m.spare_part_number, b"VM1-SPARE-001");
        set(&mut m.ecu_sw_number, b"VM1-SW-001");
        set(&mut m.supplier_sw_number, b"SUP-SW-VM1-001");
        set(&mut m.supplier_sw_version, b"1.2.0");
        set(&mut m.odx_file_id, b"ODX-VM1-V1");
        set(&mut m.system_name, b"VM1-Linux");
        set(&mut m.programming_date, b"20260604");
        set(&mut m.tester_serial, b"SOVD-OTA");
        m
    }

    /// Construct a VmBackend (vm1) with images_dir + provisioned HSM,
    /// inject a Verified package carrying `meta`, and point the flash
    /// transfer at it so `ivd_sign_staged_bank` picks up its identity.
    fn backend_with_package(
        tag: &str,
        meta: ImageMeta,
    ) -> (VmBackend<MemBlockDevice>, PathBuf, PathBuf) {
        let images_dir = std::env::temp_dir().join(format!("vm-mgr-identity-img-{tag}"));
        let _ = std::fs::remove_dir_all(&images_dir);
        std::fs::create_dir_all(&images_dir).unwrap();

        let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
        let mut boot = NvBootState::default();
        nv.write_boot_state(&mut boot).unwrap();
        let nv = Arc::new(Mutex::new(nv));

        let (hsm, keystore) = provisioned_hsm(tag);

        let backend = VmBackend::with_options(
            BankSet::Vm1,
            nv,
            Arc::new(NoopManifest),
            Arc::new(NoopSecurity),
            ComponentConfig::default(),
            None,
            Some(images_dir.clone()),
        )
        .with_hsm_provider(hsm);

        // Stage a payload file in the target (bank_b) so the bank isn't
        // payload-empty and signing actually runs.
        let bank_dir = images_dir.join("vm1").join("bank_b");
        std::fs::create_dir_all(&bank_dir).unwrap();
        std::fs::write(bank_dir.join("rootfs.img"), b"vm1 rootfs bytes").unwrap();

        // Inject a Verified package + a flash transfer pointing at it.
        let pkg_id = "pkg-1".to_string();
        backend.packages.lock().unwrap().insert(
            pkg_id.clone(),
            StoredPackage {
                id: pkg_id.clone(),
                validated: ValidatedFirmware {
                    bank_set: BankSet::Vm1,
                    manifest_type: ManifestType::Firmware,
                    image_meta: meta,
                    image_data: Vec::new(),
                    version_display: "1.2.0".into(),
                    image_sha256: Some([0xAB; 32]),
                    image_size: Some(16),
                    raw_envelope: None,
                    streamed_files: Vec::new(),
                },
                status: PackageStatus::Verified,
            },
        );
        *backend.flash_transfer.lock().unwrap() = Some(FlashTransferState {
            transfer_id: "t1".into(),
            package_id: pkg_id,
            state: FlashState::AwaitingActivation,
            image_size: 16,
            verify_baseline_boot_id: None,
            streamed_files: Vec::new(),
        });

        (backend, images_dir, keystore)
    }

    fn cleanup(images_dir: &Path, keystore: &Path) {
        let _ = std::fs::remove_dir_all(images_dir);
        let _ = std::fs::remove_dir_all(keystore);
    }

    #[test]
    fn install_sign_then_read_identity_roundtrips_image_meta() {
        let (backend, images_dir, keystore) =
            backend_with_package("roundtrip", sample_image_meta());

        // Sign bank_b (the inactive/target bank) with the package identity.
        backend.ivd_sign_staged_bank(Bank::B).unwrap();

        // read_identity must return exactly what ImageMeta projected.
        let id = backend.verified_bank_identity(Bank::B).unwrap();
        assert_eq!(id, sample_image_meta().to_ivd_identity());
        assert_eq!(id.version, "1.2.0");
        assert_eq!(id.ecu_sw_number, "VM1-SW-001");
        assert_eq!(id.system_name, "VM1-Linux");

        cleanup(&images_dir, &keystore);
    }

    #[tokio::test]
    async fn read_data_serves_identity_dids_from_manifest_not_nv() {
        let (backend, images_dir, keystore) = backend_with_package("readdata", sample_image_meta());

        // Bank_b is the target; make the backend RUN on bank_b so the
        // identity overlay reads the bank we just signed.
        *backend.running_bank.lock().unwrap() = Bank::B;
        backend.ivd_sign_staged_bank(Bank::B).unwrap();

        // NvFwMeta has NO identity fields, so this proves the values come
        // from the signed manifest. Refresh the cache for the running bank.
        {
            let nv = backend.nv.lock().unwrap();
            backend.refresh_did_cache_locked(&nv);
        }

        let want = [
            ("fw_version", "1.2.0"),
            ("ecu_sw_number", "VM1-SW-001"),
            ("supplier_sw_number", "SUP-SW-VM1-001"),
            ("supplier_sw_version", "1.2.0"),
            ("system_name", "VM1-Linux"),
            ("tester_serial", "SOVD-OTA"),
            ("programming_date", "20260604"),
            ("spare_part_number", "VM1-SPARE-001"),
            ("odx_file_id", "ODX-VM1-V1"),
        ];
        for (param, expected) in want {
            let vals = backend.read_data(&[param.to_string()]).await.unwrap();
            assert_eq!(vals.len(), 1, "{param}");
            assert_eq!(
                vals[0].value,
                serde_json::Value::String(expected.to_string()),
                "DID {param} should be served from the signed IVD manifest"
            );
        }

        cleanup(&images_dir, &keystore);
    }

    #[tokio::test]
    async fn read_data_identity_did_unavailable_before_sign() {
        // Before any manifest is signed, the identity DIDs are not in the
        // cache → read_data reports parameter-not-found (they no longer
        // come from NV).
        let (backend, images_dir, keystore) = backend_with_package("presign", sample_image_meta());
        *backend.running_bank.lock().unwrap() = Bank::B;
        // No ivd_sign_staged_bank call; bank_b has a payload file but no
        // manifest yet.
        {
            let nv = backend.nv.lock().unwrap();
            backend.refresh_did_cache_locked(&nv);
        }
        let err = backend
            .read_data(&["fw_version".to_string()])
            .await
            .unwrap_err();
        assert!(matches!(err, BackendError::ParameterNotFound(_)));

        cleanup(&images_dir, &keystore);
    }

    #[test]
    fn tampered_manifest_identity_is_refused() {
        let (backend, images_dir, keystore) = backend_with_package("tamper", sample_image_meta());
        backend.ivd_sign_staged_bank(Bank::B).unwrap();

        // Flip a byte of the signed manifest — signature no longer matches.
        let mpath = images_dir
            .join("vm1")
            .join("bank_b")
            .join(hsm::ivd::IVD_MANIFEST_FILE);
        let mut bytes = std::fs::read(&mpath).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&mpath, &bytes).unwrap();

        // The signature check rejects it → no identity served.
        assert!(backend.verified_bank_identity(Bank::B).is_none());
        assert!(backend.identity_did_bytes(Bank::B).is_empty());

        cleanup(&images_dir, &keystore);
    }

    #[tokio::test]
    async fn identity_cache_invalidates_on_nv_write() {
        // Cache invalidation rides on NvWriteGuard::drop. Sign with one
        // identity, populate cache, then re-sign the SAME bank with a new
        // identity and trigger an NV write — the cache must reflect the new
        // version, proving install/commit invalidate it.
        let (backend, images_dir, keystore) =
            backend_with_package("invalidate", sample_image_meta());
        *backend.running_bank.lock().unwrap() = Bank::B;
        backend.ivd_sign_staged_bank(Bank::B).unwrap();
        {
            let nv = backend.nv.lock().unwrap();
            backend.refresh_did_cache_locked(&nv);
        }
        let vals = backend
            .read_data(&["fw_version".to_string()])
            .await
            .unwrap();
        assert_eq!(vals[0].value, serde_json::json!("1.2.0"));

        // Re-sign bank_b with a bumped version (simulating a new install
        // landing on this bank), by swapping the package identity.
        let mut bumped = sample_image_meta();
        bumped.fw_version = [0u8; 32];
        bumped.fw_version[..5].copy_from_slice(b"2.0.0");
        backend
            .packages
            .lock()
            .unwrap()
            .get_mut("pkg-1")
            .unwrap()
            .validated
            .image_meta = bumped;
        backend.ivd_sign_staged_bank(Bank::B).unwrap();

        // Any NV write refreshes the cache via NvWriteGuard::drop.
        {
            let mut guard = backend.nv_write().unwrap();
            let mut boot = guard.read_boot_state().unwrap();
            let _ = guard.write_boot_state(&mut boot);
        }

        let vals = backend
            .read_data(&["fw_version".to_string()])
            .await
            .unwrap();
        assert_eq!(
            vals[0].value,
            serde_json::json!("2.0.0"),
            "cache must reflect the re-signed manifest identity after an NV write"
        );

        cleanup(&images_dir, &keystore);
    }

    // -----------------------------------------------------------------
    // Vendor data parameter: x-sumo-installed-manifest
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn installed_manifest_param_listed_and_read_when_committed() {
        let (backend, images_dir, keystore) = backend_with_package("ivdread", sample_image_meta());
        // Run on bank_b (the bank we sign) so the committed manifest is the
        // running one the vendor param serves.
        *backend.running_bank.lock().unwrap() = Bank::B;
        backend.ivd_sign_staged_bank(Bank::B).unwrap();

        // list_parameters advertises the vendor param (IdentData, read-only).
        let params = backend.list_parameters().await.unwrap();
        let p = params
            .iter()
            .find(|p| p.id == INSTALLED_MANIFEST_PARAM_ID)
            .expect("x-sumo-installed-manifest must be listed when a manifest exists");
        assert!(p.read_only);
        assert_eq!(p.category, Some(DataCategory::IdentData));
        assert!(p.did.is_none());

        // read_data returns the structured JSON in `value`.
        let vals = backend
            .read_data(&[INSTALLED_MANIFEST_PARAM_ID.to_string()])
            .await
            .unwrap();
        assert_eq!(vals.len(), 1);
        let v = &vals[0].value;

        // gen + identity come straight from the signed manifest.
        assert_eq!(v["ivd_version"], serde_json::json!(3));
        assert_eq!(v["identity"]["version"], serde_json::json!("1.2.0"));
        assert_eq!(
            v["identity"]["ecu_sw_number"],
            serde_json::json!("VM1-SW-001")
        );
        assert_eq!(v["identity"]["system_name"], serde_json::json!("VM1-Linux"));

        // files[]: each entry has path + lowercase-hex sha256 (64 chars).
        let files = v["files"].as_array().expect("files array");
        assert!(files
            .iter()
            .any(|f| f["path"] == serde_json::json!("rootfs.img")));
        for f in files {
            let sha = f["sha256"].as_str().expect("sha256 hex string");
            assert_eq!(sha.len(), 64, "sha256 must be 32-byte lowercase hex");
            assert!(sha
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        }

        // The two base64 fields decode and re-verify against the HSM,
        // proving they're the exact signed artefacts (downstream re-verify).
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let sig = b64
            .decode(v["signature_b64"].as_str().unwrap())
            .expect("signature_b64 decodes");
        let mbytes = b64
            .decode(v["manifest_b64"].as_str().unwrap())
            .expect("manifest_b64 decodes");
        // manifest_b64 must equal the on-disk signed bytes.
        let on_disk = std::fs::read(
            images_dir
                .join("vm1")
                .join("bank_b")
                .join(hsm::ivd::IVD_MANIFEST_FILE),
        )
        .unwrap();
        assert_eq!(mbytes, on_disk);
        // Re-verify the signature over the manifest bytes via the HSM.
        let ok = {
            let hsm = backend.hsm_provider.as_ref().unwrap().lock().unwrap();
            hsm.verify(hsm::ivd::IVD_KEY_ID, &mbytes, &sig).unwrap()
        };
        assert!(
            ok,
            "decoded signature must verify over decoded manifest bytes"
        );

        cleanup(&images_dir, &keystore);
    }

    #[tokio::test]
    async fn installed_manifest_param_absent_and_404_without_manifest() {
        // No ivd_sign_staged_bank call → the running bank has a payload file
        // but no signed manifest yet (mirrors no-HSM smoke / never-flashed).
        let (backend, images_dir, keystore) = backend_with_package("ivdnone", sample_image_meta());
        *backend.running_bank.lock().unwrap() = Bank::B;

        // Not advertised.
        let params = backend.list_parameters().await.unwrap();
        assert!(
            !params.iter().any(|p| p.id == INSTALLED_MANIFEST_PARAM_ID),
            "vendor param must be absent when no committed manifest exists"
        );

        // Read 404s (EntityNotFound → HTTP 404).
        let err = backend
            .read_data(&[INSTALLED_MANIFEST_PARAM_ID.to_string()])
            .await
            .unwrap_err();
        assert!(
            matches!(err, BackendError::EntityNotFound(_)),
            "expected EntityNotFound (404), got {err:?}"
        );
        assert_eq!(err.status_code(), 404);

        cleanup(&images_dir, &keystore);
    }

    #[tokio::test]
    async fn installed_manifest_param_refused_when_tampered() {
        let (backend, images_dir, keystore) =
            backend_with_package("ivdtamper", sample_image_meta());
        *backend.running_bank.lock().unwrap() = Bank::B;
        backend.ivd_sign_staged_bank(Bank::B).unwrap();

        // Flip a byte of the signed manifest — signature no longer matches.
        let mpath = images_dir
            .join("vm1")
            .join("bank_b")
            .join(hsm::ivd::IVD_MANIFEST_FILE);
        let mut bytes = std::fs::read(&mpath).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&mpath, &bytes).unwrap();

        // A tampered manifest must not be served — invalidate the cache
        // (an NV write would normally do this) so the re-read hits disk.
        {
            let nv = backend.nv.lock().unwrap();
            backend.refresh_did_cache_locked(&nv);
        }
        let err = backend
            .read_data(&[INSTALLED_MANIFEST_PARAM_ID.to_string()])
            .await
            .unwrap_err();
        assert!(matches!(err, BackendError::EntityNotFound(_)));

        cleanup(&images_dir, &keystore);
    }
}
