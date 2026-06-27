//! ComponentBackend — DiagnosticBackend implementation for component-mgr bank sets.
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
use std::path::PathBuf;
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

use machine_mgr::bank_provider::{BankProvider, FirmwareIdentity, InstalledFirmware};

use crate::bank_provider::IvdBankProvider;
use crate::did;
use crate::manifest_provider::{ManifestProvider, ManifestType, ValidatedFirmware};
use crate::ota;
use crate::sovd::security::SecurityProvider;

/// Vendor SOVD data-parameter id for the committed bank's signed IVD
/// manifest. `x-sumo-` prefix per ISO 17978-3 Table 70 vendor-extension
/// namespacing — the route is plain `/data/{id}` (SOVDd stays spec-pure /
/// format-agnostic); the vendor semantics live entirely here in component-mgr.
pub const INSTALLED_MANIFEST_PARAM_ID: &str = "x-sumo-installed-manifest";

/// Vendor SOVD data-parameter id for this component's **update-mode** — how it
/// updates: A/B-banked + trial + rollback, vs single-bank write-through &
/// irreversible (the HSM keystore). A STABLE per-component config property,
/// readable any time (even pre-flash), so an offboard twin can sync
/// rollback-capability the same way it syncs firmware identity. Same `x-sumo-`
/// vendor namespace (SOVDd stays spec-pure; the semantics live here in component-mgr).
pub const UPDATE_MODE_PARAM_ID: &str = "x-sumo-update-mode";

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
///   decompressed *inner* content straight through the bank provider to
///   avoid doubling flash I/O).  So re-verification asks the provider to
///   re-read the staged `(bank, name)` and compare against the inner
///   SHA-256 the streaming pipeline captured at write time — which is
///   itself the manifest's declared `image_digest`, already verified
///   against ciphertext during upload.  Catches on-disk corruption
///   between upload and finalize; doesn't and can't re-verify the
///   outer-on-the-wire hash post-stream.  Stored as `(bank, name)` (not
///   a path) so the provider owns the on-medium layout.
enum UploadedPartLocation {
    Manifest {
        upload_sha256: [u8; 32],
    },
    OnDisk {
        bank: Bank,
        name: String,
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

/// Per-component configuration for ComponentBackend behavior.
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
// ComponentBackend
// ---------------------------------------------------------------------------

pub struct ComponentBackend<D: BlockDevice + Send + 'static> {
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
    /// The node-level update-transaction coordinator (the "one transaction at a
    /// time" gate), shared across every component on this node. `None` until
    /// `vm-sovd` injects it via [`with_node_coordinator`](Self::with_node_coordinator);
    /// when set, `ensure_flash_can_start` consults it. See `machine_mgr::node_update`
    /// + docs/design/node-update-state.md.
    node_coordinator: Option<Arc<machine_mgr::node_update::NodeCoordinator>>,
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
    /// Crypto handle (e.g. supernova's shared link-B `LinkBClient`, or a SimHsm).
    /// The HSM-keys provision path builds the CEK `HsmKeyUnwrap` via `from_crypto`
    /// so device-decryption unwrap routes through `HsmCryptoProvider`. Required
    /// once the HSM is provisioned — the provision path errors without it.
    /// Threaded from `FactoryDeps::hsm_crypto` via
    /// [`with_hsm_crypto`](Self::with_hsm_crypto).
    hsm_crypto: Option<Arc<dyn hsm::HsmCryptoProvider>>,
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
    /// `(bank, installed)`: the bank the cached firmware was read for, so a
    /// running-bank flip (ecu_reset) is detected and re-verified. `Arc` so
    /// readers clone cheaply without holding the lock across the JSON
    /// build. Invalidated to `None` on every NV write via
    /// `NvWriteGuard::drop` (same trigger as `did_cache`); the next reader
    /// re-populates lazily.
    verified_manifest_cache: Mutex<Option<(Bank, Arc<InstalledFirmware>)>>,
    /// The per-kind A/B storage + lifecycle seam — the engine's ONLY bank
    /// handle. Owns every bank touch: target selection, prepare/seed, payload
    /// sinks, IVD seal, installed-firmware read-back, activator-then-flip
    /// activation, commit/rollback, reset-kind. Built as an `IvdBankProvider`
    /// in `with_options` (and rebuilt by the `with_bank_spec` /
    /// `with_bank_activator` builders, which change its inputs); a later phase
    /// moves construction to component-factory. The concrete type is no longer
    /// retained — a non-IVD provider (e.g. RT raw-partition) drops in here
    /// without touching the engine.
    bank_provider: Arc<dyn BankProvider>,
    /// Set by [`Self::with_bank_provider`] when an explicit provider has been
    /// injected. While `true`, [`Self::rebuild_bank_provider`] is a no-op so a
    /// later `with_bank_spec` / `with_bank_activator` in the builder chain does
    /// NOT clobber the override with a fresh `IvdBankProvider`. Builder order
    /// therefore matters: call `with_bank_spec` / `with_bank_activator` (which
    /// feed an `IvdBankProvider`) FIRST, then `with_bank_provider` LAST to
    /// replace the whole provider — anything after `with_bank_provider` that
    /// would rebuild is intentionally ignored.
    bank_provider_override: bool,
    /// The bank activator the (non-overridden) default `IvdBankProvider` is
    /// rebuilt with. Stored so a later `with_hsm_crypto` rebuild (which threads
    /// the crypto handle into the default provider) preserves the activator set
    /// by an earlier `with_bank_activator`. `None` until `with_bank_activator`.
    bank_activator: Option<Arc<dyn machine_mgr::BankActivator>>,
    /// Optional hook invoked after a successful HSM keystore provision (the
    /// `finalize_flash` HSM path) so the orchestrator reloads the backend against
    /// the freshly-written keystore. The HSM daemon's lifecycle is owned
    /// externally now (supernova spawns the link-B backend), so this is the only
    /// reload path — there is no in-process daemon restart. `None` (the default)
    /// skips the reload. Threaded from `FactoryDeps::post_provision_reload` via
    /// [`with_post_provision_reload`](Self::with_post_provision_reload).
    post_provision_reload: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl<D: BlockDevice + Send + 'static> ComponentBackend<D> {
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
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_options(
        bank_set: BankSet,
        nv: Arc<Mutex<NvStore<D>>>,
        manifest_provider: Arc<dyn ManifestProvider>,
        security_provider: Arc<dyn SecurityProvider>,
        config: ComponentConfig,
        vm_service_addr: Option<String>,
        images_dir: Option<PathBuf>,
        hsm_provider: Option<Arc<Mutex<dyn hsm::HsmProvider>>>,
    ) -> Self {
        let (id, name, desc) = match bank_set {
            BankSet::Hsm => ("hsm", "HSM Key Store", "Hardware Security Module"),
            BankSet::Bootloader => ("bootloader", "Bootloader", "Reserved bootloader bank set"),
            BankSet::Os => (
                "host-os",
                "Host OS",
                "Host OS (IFS + rootfs) A/B bank set; carries the self-updating app slot",
            ),
            BankSet::Rt => ("rt", "Realtime", "Realtime / Cortex-M7 core bank set"),
            BankSet::Vm1 => ("vm1", "VM1", "Virtual machine slot 1"),
            BankSet::Vm2 => ("vm2", "VM2", "Virtual machine slot 2"),
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

        // Build the initial bank provider from the same nv/bank_set/images_dir/
        // hsm it holds (activator still None here; `with_bank_activator` rebuilds
        // it, as does `with_bank_spec` for the dir name). Clones the Arcs — the
        // struct literal below moves the originals into the backend's fields.
        let bank_spec = crate::bank_spec::BankSetSpec::for_well_known(bank_set);
        let bank_provider: Arc<dyn BankProvider> = Arc::new(IvdBankProvider::new(
            nv.clone(),
            bank_set,
            config.single_bank,
            images_dir.clone(),
            bank_spec.dir_name.clone(),
            hsm_provider.clone(),
            None,
            // No boot selector here: the backend's inline provider keeps the
            // NV/symlink path. component-factory builds a selector-aware
            // `IvdBankProvider` and injects it via `with_bank_provider`.
            None,
        ));

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
            bank_spec,
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
            hsm_provider,
            // Defaults to the `dyn HsmProvider` path; component-factory injects a
            // crypto-only handle via `with_hsm_crypto` when link-B is configured.
            hsm_crypto: None,
            health_probe: None,
            did_cache: std::sync::RwLock::new(std::collections::HashMap::new()),
            manifest_describe: Mutex::new(HashMap::new()),
            verified_manifest_cache: Mutex::new(None),
            bank_provider,
            bank_provider_override: false,
            bank_activator: None,
            node_coordinator: None,
            post_provision_reload: None,
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

    /// Inject the shared node update-transaction coordinator (the `start_flash`
    /// gate). `vm-sovd` builds ONE coordinator and hands the same `Arc` to every
    /// component on the node, so the gate sees one node-wide staging state. See
    /// `machine_mgr::node_update::NodeCoordinator`.
    pub fn with_node_coordinator(
        mut self,
        coordinator: Arc<machine_mgr::node_update::NodeCoordinator>,
    ) -> Self {
        self.node_coordinator = Some(coordinator);
        self
    }

    /// Set the post-provision reload hook. When set, the HSM provision path
    /// (`finalize_flash`) calls it after provisioning so the orchestrator reloads
    /// the externally-owned HSM daemon (e.g. the link-B backend) against the new
    /// keystore. Leaving it unset (the default) skips the reload — there is no
    /// in-process daemon restart. Threaded from `FactoryDeps::post_provision_reload`.
    pub fn with_post_provision_reload(mut self, reload: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.post_provision_reload = Some(reload);
        self
    }

    /// Inject the crypto handle (e.g. supernova's shared link-B `LinkBClient`, or
    /// a SimHsm). The HSM-keys provision path builds the CEK `HsmKeyUnwrap` via
    /// `from_crypto` so device-decryption unwrap routes through
    /// `HsmCryptoProvider`. Required once the HSM is provisioned — the provision
    /// path errors without it. Threaded from `FactoryDeps::hsm_crypto`.
    pub fn with_hsm_crypto(mut self, crypto: Arc<dyn hsm::HsmCryptoProvider>) -> Self {
        self.hsm_crypto = Some(crypto);
        // Thread the crypto handle into the (non-overridden) default bank
        // provider so its IVD `seal` can sign — preserving any activator set by
        // an earlier `with_bank_activator`. A `with_bank_provider` override
        // already carries its own crypto handle, so this rebuild is skipped then.
        self.rebuild_bank_provider();
        self
    }

    /// Override the bank-set spec (on-disk dir + URI→filename layout).
    /// Constructors default to `BankSetSpec::for_well_known(bank_set)`;
    /// component-factory uses this to inject deployment-config-driven
    /// values once Phase 3 wires the ComponentSpec → BankSetSpec path.
    pub fn with_bank_spec(mut self, spec: crate::bank_spec::BankSetSpec) -> Self {
        self.bank_spec = spec;
        // The provider keys its on-disk layout off `bank_spec.dir_name`; rebuild
        // it so a deployment-supplied dir name takes effect. `with_bank_spec`
        // precedes `with_bank_activator` in the builder order, so no activator is
        // stored yet (`self.bank_activator` is still `None`).
        self.rebuild_bank_provider();
        self
    }

    /// Set a bank activator for post-install bank activation.
    pub fn with_bank_activator(mut self, activator: Arc<dyn machine_mgr::BankActivator>) -> Self {
        // The provider owns the activator (used by `activate` + `reset_kind`).
        // Store it so later rebuilds (e.g. `with_hsm_crypto`) keep it, then
        // rebuild so the just-set activator is the one the provider invokes.
        // Must be called AFTER `with_bank_spec`.
        self.bank_activator = Some(activator);
        self.rebuild_bank_provider();
        self
    }

    /// Rebuild the bank provider from the backend's current bank-relevant state
    /// (`bank_activator` + `hsm_crypto` included) and re-point the `dyn` handle at
    /// the new object. Called by the `with_bank_spec` / `with_bank_activator` /
    /// `with_hsm_crypto` builders that change its inputs. `running_bank` is
    /// re-seeded from NV inside the provider — idempotent at construction.
    fn rebuild_bank_provider(&mut self) {
        // An explicit provider injected via `with_bank_provider` wins: never
        // rebuild over it. `with_bank_spec` / `with_bank_activator` /
        // `with_hsm_crypto` calls that land after the override are silently
        // no-ops on the provider (their other side effects still apply).
        if self.bank_provider_override {
            return;
        }
        let mut provider = IvdBankProvider::new(
            self.nv.clone(),
            self.bank_set,
            self.config.single_bank,
            self.images_dir.clone(),
            self.bank_spec.dir_name.clone(),
            self.hsm_provider.clone(),
            self.bank_activator.clone(),
            // No boot selector on the rebuild path: a selector-aware provider
            // is injected wholesale via `with_bank_provider` (which sets the
            // override so this rebuild is skipped). Keeps the NV/symlink path
            // for the default in-backend provider + tests.
            None,
        );
        // Thread the crypto handle so the default provider's IVD `seal` can sign.
        if let Some(crypto) = self.hsm_crypto.clone() {
            provider = provider.with_hsm_crypto(crypto);
        }
        self.bank_provider = Arc::new(provider);
    }

    /// Replace the default `IvdBankProvider` with an explicit `BankProvider`
    /// (e.g. supernova-mm's RT raw-partition provider). Sets the override flag
    /// so a subsequent `rebuild_bank_provider` (triggered by `with_bank_spec` /
    /// `with_bank_activator`) does NOT clobber it.
    ///
    /// **Builder order:** call `with_bank_spec` and `with_bank_activator` FIRST
    /// (they rebuild the default `IvdBankProvider` and set `bank_spec`), then
    /// `with_bank_provider` LAST to swap in the explicit provider. Any rebuild-
    /// triggering builder placed after this is intentionally ignored.
    pub fn with_bank_provider(mut self, provider: Arc<dyn BankProvider>) -> Self {
        self.bank_provider = provider;
        self.bank_provider_override = true;
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
    // Accessors used by component_adapter::ComponentAdapter.
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

    /// Reset kind declared by this component's bank provider (folds in the
    /// activator's `reset_kind`, or [`ResetKind::Local`] when no activator is
    /// configured — e.g. VM components without a custom activator, whose
    /// qvm/process cycle is local). `derive_capabilities` reads this to
    /// populate `FlashCaps.reset_kind`.
    pub fn reset_kind(&self) -> machine_mgr::ResetKind {
        self.bank_provider.reset_kind()
    }

    /// Render this component's update-mode as the `x-sumo-update-mode` JSON
    /// value: `banked` (A/B + trial + rollback) vs `singleshot` (single-bank,
    /// write-through, irreversible — the HSM keystore), plus the flash-cap
    /// fields an offboard twin keys its composition guard on. Stable config —
    /// no NV / manifest dependency, so it serves even pre-flash.
    fn update_mode_json(&self) -> serde_json::Value {
        let update_mode = if self.config.single_bank {
            "singleshot"
        } else {
            "banked"
        };
        serde_json::json!({
            "update_mode": update_mode,
            "supports_rollback": self.config.supports_rollback,
            "dual_bank": !self.config.single_bank,
            "reset_kind": self.reset_kind(),
        })
    }

    /// The bank an OTA upload should write to — delegated to the bank
    /// provider (the *inactive* bank for dual-bank, `Bank::A` for single-bank,
    /// resolved from the boot selector / NV `active_bank`).
    fn determine_target_bank(&self) -> BackendResult<Bank> {
        Ok(self.bank_provider.target_bank())
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
        // Bank mechanics (seed → skip-checks → HSM-provisioned gate → sign)
        // moved to `IvdBankProvider::seal`. The engine still owns the two
        // inputs that come from its OTA state: the install-time `gen` (from NV)
        // and the firmware SW identity (from the package the flash transfer
        // points at, mapped to the kind-agnostic `FirmwareIdentity`).
        let gen = self.install_gen_for(target)?;
        let identity = self.current_install_identity();
        self.bank_provider
            .seal(target, identity, gen)
            .map_err(|e| BackendError::Internal(e.to_string()))
    }

    /// Compute the install-time generation counter (`gen`) directly from NV
    /// state. Must agree with what `ota::install_inner` writes into target's
    /// NvFwMeta — both derive it as `committed_bank.gen + 1`. Computed here
    /// (not read back from NvFwMeta) because in the multi-POST upload path the
    /// sign happens at "all payloads received", before `install_precomputed`
    /// writes the target's NvFwMeta at transferexit. The OTA flow is serialized
    /// (start_flash rejects concurrent flashes), so both arrive at the same
    /// gen. The committed bank is whichever of {active, active.other()} has
    /// committed=true.
    fn install_gen_for(&self, _target: Bank) -> BackendResult<u64> {
        let nv = self
            .nv
            .lock()
            .map_err(|_| BackendError::Internal("ivd sign: nv mutex poisoned".into()))?;
        let state = nv
            .read_boot_state()
            .ok_or_else(|| BackendError::Internal("ivd sign: NV boot state missing".into()))?;
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
        Ok(committed_gen + 1)
    }

    /// The firmware SW identity to seal into the IVD manifest being signed:
    /// derived from the SUIT-extracted `ImageMeta` of the package the current
    /// flash transfer points at, mapped to the kind-agnostic
    /// [`FirmwareIdentity`]. All-`None` when no package is in scope (e.g. a
    /// re-sign with no active transfer) — the manifest then carries a blank
    /// identity, which reads back as all-NUL DIDs (prior behaviour preserved).
    fn current_install_identity(&self) -> FirmwareIdentity {
        let package_id = {
            let ft = self.flash_transfer.lock().ok();
            ft.and_then(|g| g.as_ref().map(|t| t.package_id.clone()))
                .unwrap_or_default()
        };
        if package_id.is_empty() {
            return FirmwareIdentity::default();
        }
        let packages = match self.packages.lock() {
            Ok(p) => p,
            Err(_) => return FirmwareIdentity::default(),
        };
        packages
            .get(&package_id)
            .map(|p| p.validated.image_meta.to_firmware_identity())
            .unwrap_or_default()
    }

    /// Bank to serve installed-manifest / identity from: the boot selector's
    /// active bank (the authority the VM boots), falling back to the
    /// `running_bank` cache only when the selector has no selection.
    ///
    /// `selected_bank()` is the selector's selection ALONE (`None` when no
    /// selector is wired — tests / the no-HSM smoke path / RT-without-config);
    /// it deliberately does NOT use the provider's own NV-seeded fallback, so
    /// we fall back to THIS backend's live `running_bank` (updated on
    /// `ecu_reset`), not the provider's frozen construction-time copy. The
    /// previous serve path read `*self.running_bank.lock()` directly and so
    /// missed the just-flashed bank the selector had already switched to.
    fn serving_bank(&self) -> Bank {
        self.bank_provider
            .selected_bank()
            .unwrap_or_else(|| *self.running_bank.lock().unwrap())
    }

    /// Read a bank's installed firmware **report-only** via the bank provider
    /// (decode the on-disk signed manifest; NO HSM verify) and return it as
    /// [`InstalledFirmware`], caching it per-bank so repeated diagnostics reads
    /// share one decode. The cache is invalidated on every NV write (see
    /// `refresh_did_cache_locked`), so the served firmware always reflects the
    /// latest install/commit/ecu_reset.
    ///
    /// Returns `Some` whenever the manifest file is present + decodable, `None`
    /// only on `NotInstalled` (no images_dir, no manifest yet) or a corrupt
    /// manifest. The served object carries the raw manifest bytes + signature
    /// so a client verifies independently; the on-device gate stays in
    /// `verify_bank` (install/boot/launch), unchanged. The `Unverifiable` warn
    /// arm below is therefore unreachable on this report-only path — it is left
    /// in place but never fires.
    ///
    /// Used for the RUNNING/committed bank: `read_data` of the identity DIDs
    /// and the vendor `x-sumo-installed-manifest` parameter both pass
    /// `*self.running_bank`, the same bank whose identity overlay is built in
    /// `refresh_did_cache_locked`.
    fn verified_bank_manifest(&self, bank: Bank) -> Option<Arc<InstalledFirmware>> {
        // Fast path: return the cached firmware if it's for this bank.
        {
            let cache = self
                .verified_manifest_cache
                .lock()
                .expect("verified_manifest_cache poisoned");
            if let Some((cached_bank, fw)) = cache.as_ref() {
                if *cached_bank == bank {
                    tracing::info!(component = %self.entity_info.id, bank = ?bank, "ivd-route: cache hit -> serving");
                    return Some(Arc::clone(fw));
                }
            }
        }

        // Slow path: read + verify via the provider, then memoise for this bank.
        match self.bank_provider.read_installed(bank) {
            Ok(fw) => {
                tracing::info!(component = %self.entity_info.id, bank = ?bank, "ivd-route: installed firmware OK -> serving + caching");
                let fw = Arc::new(fw);
                *self
                    .verified_manifest_cache
                    .lock()
                    .expect("verified_manifest_cache poisoned") = Some((bank, Arc::clone(&fw)));
                Some(fw)
            }
            Err(machine_mgr::bank_provider::BankError::Unverifiable(msg)) => {
                tracing::warn!(
                    component = %self.entity_info.id,
                    bank_set = ?self.bank_set,
                    bank = ?bank,
                    "ivd-route: installed firmware unverifiable ({msg}); refusing to serve it",
                );
                None
            }
            Err(e) => {
                // NotInstalled / no images_dir / no HSM etc. — normal absence.
                // INFO (not debug) so a fresh-device 404 on the manifest shows
                // exactly which bank had no installed firmware and why.
                tracing::info!(
                    component = %self.entity_info.id,
                    bank = ?bank,
                    error = %e,
                    "ivd-route: no installed manifest for serving bank -> None",
                );
                None
            }
        }
    }

    /// The installed firmware's SW [`FirmwareIdentity`] for `bank` — the single
    /// source for the SW-identity DIDs (F187-F19E) and version labels now that
    /// they're out of NvFwMeta. Thin projection over
    /// [`Self::verified_bank_manifest`].
    fn verified_bank_identity(&self, bank: Bank) -> Option<FirmwareIdentity> {
        self.verified_bank_manifest(bank)
            .map(|fw| fw.identity.clone())
    }

    /// The `(did, bytes)` pairs for the 9 SW-identity DIDs of `bank`, each
    /// converted to its historical fixed-width UDS byte form. Empty when the
    /// bank has no verifiable identity (see [`Self::verified_bank_identity`]).
    fn identity_did_bytes(&self, bank: Bank) -> Vec<(u16, Vec<u8>)> {
        match self.verified_bank_manifest(bank) {
            Some(fw) => identity_to_did_bytes(&fw.identity),
            None => Vec::new(),
        }
    }

    /// Wipe the target bank dir + reclaim space — delegated to the provider's
    /// `prepare_target`. Called at flash-session start so the incoming payload
    /// lands in a clean, space-reclaimed location on the same filesystem as its
    /// final home.
    fn prepare_target_bank_dir(&self, target: Bank) -> BackendResult<()> {
        self.bank_provider
            .prepare_target(target)
            .map_err(|e| BackendError::Internal(e.to_string()))
    }

    pub fn has_hsm_provider(&self) -> bool {
        self.hsm_provider.is_some()
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

        // Node-level update-transaction gate: refuse a new flash while the node
        // owes an activation reboot for a prior staged update (the durable half —
        // survives a power cycle, unlike the in-memory flash state, which is how a
        // singleshot rt slipped through). A sibling joining the SAME transaction
        // (matching session id) is admitted, so the banked group can stage
        // together. On admit, this component joins the staging set. No-op until
        // `vm-sovd` injects the coordinator. The session id is the interim zero
        // until the campaign manifest stamps one (B5/B6); in-trial is wired with
        // the verdict lifecycle.
        if let Some(coord) = &self.node_coordinator {
            let durable = self.node_reboot_owed()?;
            coord
                .gate_new_session([0u8; 32], &self.entity_info.id, &durable, &[])
                .map_err(|r| BackendError::Busy(r.to_string()))?;
        }

        Ok(())
    }

    /// Read the node-level reboot-owed set from this node's shared NV
    /// (`NvUpdateSession`) as a [`machine_mgr::node_update::Durable`] — the durable
    /// half of the update-transaction state the gate checks. Labelled by bank set;
    /// the per-component names arrive once the coordinator holds the bank-set->id map.
    fn node_reboot_owed(&self) -> BackendResult<machine_mgr::node_update::Durable> {
        let nv = self
            .nv
            .lock()
            .map_err(|_| BackendError::Internal("nv lock".into()))?;
        let session = nv.read_update_session().unwrap_or_default();
        let reboot_owed = (0..nv_store::types::NUM_BANK_SETS)
            .filter(|&i| session.reboot_owed & (1u16 << i) != 0)
            .map(|i| {
                self.node_coordinator
                    .as_ref()
                    .map(|c| c.label(i))
                    .unwrap_or_else(|| format!("bank-set {i}"))
            })
            .collect();
        Ok(machine_mgr::node_update::Durable {
            session_id: session.session_id,
            reboot_owed,
        })
    }

    /// Set or clear this component's bit in the node-level reboot-owed record
    /// (`NvUpdateSession`) — the durable "a node reboot is owed" marker the gate
    /// checks. Read-modify-write of the shared node NV; idempotent (writes only on
    /// a change). The mirror of [`node_reboot_owed`](Self::node_reboot_owed).
    fn set_reboot_owed(&self, owed: bool) -> BackendResult<()> {
        let mut nv = self
            .nv
            .lock()
            .map_err(|_| BackendError::Internal("nv lock".into()))?;
        let mut s = nv.read_update_session().unwrap_or_default();
        let bit = 1u16 << self.bank_set.as_index();
        let before = s.reboot_owed;
        if owed {
            s.reboot_owed |= bit;
        } else {
            s.reboot_owed &= !bit;
        }
        if s.reboot_owed != before {
            nv.write_update_session(&mut s)
                .map_err(|e| BackendError::Internal(format!("nv write update-session: {e:?}")))?;
        }
        Ok(())
    }

    /// A node update-transaction for this component has resolved — committed OR
    /// rolled back. Clear its durable reboot-owed bit and drop it from the
    /// coordinator's staging, so a fully-resolved transaction returns the node to
    /// `Idle`. Called from BOTH `commit_flash` and `rollback_flash` (the two
    /// resolution points) so neither path can leave the node wedged in
    /// `RebootPending`/`Staging`. The reboot-owed clear is a no-op for banked
    /// components (they never set it) — kept for symmetry and as a safety net.
    fn resolve_node_transaction(&self) -> BackendResult<()> {
        self.set_reboot_owed(false)?;
        if let Some(coord) = &self.node_coordinator {
            coord.remove_from_staging(&self.entity_info.id);
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

            let target_name =
                crate::bank_spec::payload_target_name(self.bank_spec.layout, uri.as_str());

            // Open the payload sink through the bank provider — it owns where
            // the bytes land and creates the bank dir as needed.
            let writer = self
                .bank_provider
                .open_payload_writer(target_bank, &target_name)
                .map_err(|e| BackendError::Internal(e.to_string()))?;

            tracing::info!(
                uri = %uri,
                component = comp_idx,
                payload = %stored_payload.path.display(),
                output = %target_name,
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
                writer,
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
                target_name,
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
            // validate it before launch. `ivd_sign_staged_bank` (via the
            // provider's `seal`) first seeds unstreamed files from the active
            // bank so the signature covers a complete bank, then signs;
            // soft-skips when the HSM has no ivd-signing slot yet.
            let target_bank = self.determine_target_bank()?;
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
        let target_name = crate::bank_spec::payload_target_name(self.bank_spec.layout, &uri);

        // Open the payload sink through the bank provider — it owns where the
        // bytes land and creates the bank dir as needed.
        let writer = self
            .bank_provider
            .open_payload_writer(target_bank, &target_name)
            .map_err(|e| BackendError::Internal(e.to_string()))?;

        tracing::info!(
            component = comp_idx,
            uri = %uri,
            target = %target_name,
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
            writer,
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
            target_name,
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
            // Bank dir is content-final; IVD-sign before the caller proceeds
            // to finalize_flash. `ivd_sign_staged_bank` (via the provider's
            // `seal`) seeds unstreamed files from the active bank first so the
            // signature covers a complete bank.
            let target_bank = self.determine_target_bank()?;
            self.ivd_sign_staged_bank(target_bank)?;
        }

        let id = self.next_id();
        self.uploaded_parts.lock().unwrap().insert(
            id.clone(),
            UploadedPartLocation::OnDisk {
                bank: target_bank,
                name: target_name.clone(),
                inner_sha256: image_hash,
            },
        );
        Ok(id)
    }

    /// Authorization gate for privileged flash operations.
    ///
    /// supernova is a **native SOVD server**, not a UDS ECU front, so privileged
    /// `/updates` is authorized by the **bearer token** (ISO 17978-3 §5.4.4), not
    /// a UDS programming session. The legacy UDS session/security dance has been
    /// dropped from this path — it leaked the UDS model into a native server, and
    /// the native-SOVD drivers (rig, provision) never run it. `modes/session` +
    /// `modes/security` stay for clients that still set them (classic campaign
    /// unlock), but are no longer *required* to flash.
    ///
    /// Until the SOVDd TLS+JWT auth slice lands the bearer token isn't visible to
    /// the backend, so privileged flash is accepted and we warn. Flip this to a
    /// 401 token check (absent/invalid token) once auth enforces.
    fn require_flash_access(&self) -> BackendResult<()> {
        let in_programming = *self.session.lock().unwrap() == SessionState::Programming;
        let unlocked = self.security.lock().unwrap().phase == SecurityPhase::Unlocked;
        if !(in_programming && unlocked) {
            tracing::warn!(
                bank_set = ?self.bank_set,
                "privileged flash operation accepted unauthenticated — authorize with a \
                 bearer token (ISO 17978-3 §5.4.4) once the SOVD auth slice enforces it"
            );
        }
        Ok(())
    }

    pub(crate) fn nv_bytes_to_string(data: &[u8]) -> String {
        let end = data.iter().position(|&c| c == 0).unwrap_or(data.len());
        String::from_utf8_lossy(&data[..end]).to_string()
    }

    /// Build the `?bank=` query suffix for the vm-service notify URL.
    /// `Some(Bank::A)` ⇒ `"?bank=a"`, `Some(Bank::B)` ⇒ `"?bank=b"`,
    /// `None` ⇒ `""` (vm-service then leaves its `def.bank` untouched).
    fn bank_query(bank: Option<Bank>) -> &'static str {
        match bank {
            Some(Bank::A) => "?bank=a",
            Some(Bank::B) => "?bank=b",
            None => "",
        }
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
    async fn notify_vm_service(
        addr: &str,
        vm_name: &str,
        action: &str,
        bank: Option<Bank>,
    ) -> Result<(), String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| format!("connect to vm-service: {e}"))?;

        // Carry the just-activated bank as a `?bank=` query so vm-service
        // re-resolves the launch bank (via `set_vm_bank`) before relaunching.
        // Absent ⇒ vm-service leaves its `def.bank` untouched (back-compat).
        let query = Self::bank_query(bank);
        let request = format!(
            "POST /vms/{vm_name}/{action}{query} HTTP/1.1\r\n\
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
// Use `ComponentBackend::nv_write()` to acquire. Read sites should keep using
// `self.nv.lock()` directly — they don't need the refresh, and going
// through the guard would do useless work.
// ---------------------------------------------------------------------------

struct NvWriteGuard<'a, D: BlockDevice + Send + 'static> {
    backend: &'a ComponentBackend<D>,
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
impl<D: BlockDevice + Send + 'static> DiagnosticBackend for ComponentBackend<D> {
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

        // Bank + manifest presence are resolved ONCE here and reused for both
        // the identity-DID list gate (below) and the vendor
        // `x-sumo-installed-manifest` advertisement (further down) — same
        // authority `read_data` / the cache overlay use. `verified_bank_manifest`
        // memoises per-bank, so the later x-sumo check is a cache hit.
        let serving = self.serving_bank();
        let manifest_present = self.verified_bank_manifest(serving).is_some();

        let mut params: Vec<ParameterInfo> = DID_REGISTRY
            .iter()
            .filter(|d| {
                has_health || (d.did != did::DID_GUEST_STATE && d.did != did::DID_HEARTBEAT_SEQ)
            })
            // Advertise the F187–F19E SW-identity DIDs ONLY when the serving
            // bank has a committed signed manifest — they read from `did_cache`
            // via the manifest overlay, so on a manifest-less bank they would
            // be LISTED but 404 on read (list/read disagreement, spec C-031).
            // Hardware-identity + factory + runtime + dynamic DIDs read from NV
            // regardless and stay listed unconditionally.
            .filter(|d| manifest_present || !is_identity_did(d.did))
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

        // Vendor data parameter: the booted bank's signed IVD manifest
        // (per-file inventory + identity + signature). Advertised only when a
        // verifiable manifest actually exists — absent on the no-HSM smoke path
        // or a never-flashed bank, so we don't fabricate a parameter that would
        // 404 on read. Reuses the `serving` bank + `manifest_present` resolved
        // at the top (same authority gating the identity DIDs above), so this
        // and the identity-DID gate can never disagree.
        tracing::info!(component = %self.entity_info.id, serving_bank = ?serving, running_bank = ?*self.running_bank.lock().unwrap(), "ivd-route: list_data picking bank for installed-manifest advertisement");
        if manifest_present {
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

        // Vendor data parameter: this component's update-mode (banked &
        // rollbackable vs single-bank & irreversible). A STABLE config property —
        // advertised + readable unconditionally (even pre-flash), unlike the
        // installed manifest, so an offboard twin can sync rollback-capability the
        // same way it syncs firmware identity.
        params.push(ParameterInfo {
            id: UPDATE_MODE_PARAM_ID.to_string(),
            name: "Component update-mode".to_string(),
            description: Some(
                "How this component updates: banked (A/B + trial + rollback) or \
                 singleshot (single-bank, write-through, irreversible — e.g. the \
                 HSM keystore). Carries update_mode / supports_rollback / \
                 dual_bank / reset_kind. Stable per-component config; readable any \
                 time, even before first flash."
                    .to_string(),
            ),
            unit: None,
            data_type: Some("object".to_string()),
            read_only: true,
            href: format!("/vehicle/v1/components/{comp_id}/data/{UPDATE_MODE_PARAM_ID}"),
            did: None,
            category: Some(DataCategory::IdentData),
        });

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
            // Vendor parameter: the booted bank's signed IVD manifest.
            // Intercepted before `resolve_param` (which only knows
            // DID-registry / hex ids). 404 when no committed manifest exists —
            // never fabricated. Bank comes from the boot selector (the
            // authority the VM boots from), not the stale `running_bank` cache.
            if param_id == INSTALLED_MANIFEST_PARAM_ID {
                let serving = self.serving_bank();
                tracing::info!(component = %self.entity_info.id, serving_bank = ?serving, running_bank = ?*self.running_bank.lock().unwrap(), "ivd-route: read_data x-sumo-installed-manifest requested");
                let vm = match self.verified_bank_manifest(serving) {
                    Some(vm) => {
                        tracing::info!(
                            component = %self.entity_info.id,
                            bank = ?serving,
                            gen = vm.gen,
                            "ivd-route: read_data x-sumo-installed-manifest served",
                        );
                        vm
                    }
                    None => {
                        tracing::info!(
                            component = %self.entity_info.id,
                            bank = ?serving,
                            "ivd-route: read_data x-sumo-installed-manifest 404 (NotInstalled)",
                        );
                        return Err(BackendError::EntityNotFound(format!(
                            "{INSTALLED_MANIFEST_PARAM_ID}: no committed IVD manifest for {} bank {:?}",
                            self.entity_info.id, serving
                        )));
                    }
                };
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

            // Vendor parameter: this component's update-mode. Stable config —
            // always served (no 404), even pre-flash, so the offboard twin can
            // classify rollback-capability for the composition guard.
            if param_id == UPDATE_MODE_PARAM_ID {
                values.push(DataValue {
                    id: param_id.clone(),
                    name: "Component update-mode".to_string(),
                    value: self.update_mode_json(),
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
        // ComponentBackend serves). Report it as both updated (version changed) and
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

        // This path never went through `start_flash`, so it must enforce the
        // same trial-mode guard here before touching any bank. Otherwise a flash
        // issued while a trial is uncommitted resolves the target to the
        // *committed* bank (`active.other()`) and `prepare_target_bank_dir` wipes
        // the rollback target. (No-op for single-bank/HSM, which has no trial.)
        self.ensure_flash_can_start()?;

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
                streamed_files: Vec::new(),
            });
        }

        *self.upload_phase.lock().unwrap() = Some(FlashState::Transferring);

        let validated = match crate::streaming::process_envelope_stream(
            stream,
            self.manifest_provider.as_ref(),
            min_security_ver,
            Some(self.bank_provider.as_ref()),
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
                    UploadedPartLocation::OnDisk {
                        bank,
                        name,
                        inner_sha256,
                    } => UploadedPartLocation::OnDisk {
                        bank: *bank,
                        name: name.clone(),
                        inner_sha256: *inner_sha256,
                    },
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
            UploadedPartLocation::OnDisk {
                bank,
                name,
                inner_sha256,
            } => {
                // Re-read the staged part through the provider (it owns the
                // on-medium layout) and confirm the captured inner hash. Map
                // the provider error back to the wire variants the inline
                // version used: a hash mismatch is a bad request (the data on
                // disk is wrong), a read failure is our-fault internal.
                self.bank_provider
                    .verify_payload(bank, &name, &inner_sha256)
                    .map_err(|e| match e {
                        machine_mgr::bank_provider::BankError::Unverifiable(_) => {
                            BackendError::InvalidRequest(format!("verify_part {file_id}: {e}"))
                        }
                        _ => BackendError::Internal(format!("verify_part {file_id}: {e}")),
                    })
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
                        // CEK unwrap routes through the crypto handle
                        // (`HsmCryptoProvider`) — the device key never leaves the
                        // HSM. A provisioned HSM with no crypto handle is a wiring
                        // bug; surface it rather than silently skip unwrap.
                        let Some(crypto) = self.hsm_crypto.as_ref() else {
                            return Err(BackendError::Internal(
                                "HSM provisioned but no HsmCryptoProvider attached — CEK unwrap requires crypto".into(),
                            ));
                        };
                        let unwrap: std::sync::Arc<
                            dyn sumo_onboard::decryptor::KeyUnwrap + Send + Sync,
                        > = std::sync::Arc::new(hsm::HsmKeyUnwrap::from_crypto(
                            crypto.clone(),
                            hsm::KeyRole::DeviceDecryption.handle(),
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
                    streamed_files: Vec::new(),
                });
            }
            // No-op for HSM single-bank (no bank dir under images_dir; the
            // keystore lives separately) but kept for uniformity — any future
            // component with content here gets signed automatically.
            // `ivd_sign_staged_bank` (provider `seal`) seeds then signs.
            let target_bank = self.determine_target_bank()?;
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
        // (it resolves the *target* as the sibling of NV `active_bank`,
        // which install_precomputed has by then flipped, returning the
        // WRONG bank). For CRL (no install), stays None and the activator
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

        // Bank activation: route through the provider's `activate`, which runs
        // the activator (if any) then records the activation in the boot
        // selector. Use installed_bank captured from install_precomputed /
        // install above — that's the authoritative answer. Re-deriving via
        // determine_target_bank() here would return the OLD (now-inactive)
        // bank on first-ever flash because NV has been flipped, so its sibling
        // is the prior bank. `activate` runs on the bank we just wrote payloads
        // to. For VMs (no activator) `activate` only seals the selector —
        // matching the old activator-gated block that was skipped without an
        // activator.
        if !is_crl {
            let wrote_to = installed_bank.ok_or_else(|| {
                BackendError::Internal("installed_bank unset — unreachable for !is_crl".into())
            })?;
            if let Err(e) = self.bank_provider.activate(wrote_to) {
                tracing::error!(
                    bank_set = ?self.bank_set,
                    bank = ?wrote_to,
                    error = %e,
                    "bank activation failed during install finalize — rolling back"
                );
                let mut nv = self.nv_write()?;
                let _ = ota::rollback(&mut *nv, self.bank_set);
                return Err(BackendError::Internal(format!(
                    "bank activation failed: {e}"
                )));
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
                        streamed_files: Vec::new(),
                    });
                    (id, tb)
                }
            };
            // Self-sign before returning. `ivd_sign_staged_bank` (provider
            // `seal`) seeds unstreamed files from the active bank first so the
            // signature covers a complete bank, then signs; no-ops when the
            // bank dir is absent (e.g. HSM single-bank components).
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

                            // Reload the HSM so it picks up the freshly-written
                            // keystore. The daemon's lifecycle is owned externally
                            // now (supernova spawns the link-B backend); when a
                            // `post_provision_reload` hook is set, call it so the
                            // orchestrator reloads against the new keystore. There
                            // is no in-process daemon restart anymore.
                            if let Some(ref reload) = self.post_provision_reload {
                                reload();
                                tracing::info!(
                                    "HSM reloaded via post-provision hook (external daemon lifecycle)"
                                );
                            }

                            // Load keys from HSM into manifest provider.
                            // Public trust anchors come out as bytes;
                            // the device decryption key stays inside
                            // the HSM and is invoked via HsmKeyUnwrap.
                            let ka = hsm_guard.get_public_key(hsm::KeyRole::KeyAuthority).ok();
                            match hsm_guard.get_public_key(hsm::KeyRole::SoftwareAuthority) {
                                Ok(sw_key) => {
                                    drop(hsm_guard);
                                    // CEK unwrap routes through the crypto handle
                                    // (`HsmCryptoProvider`); the device key never
                                    // leaves the HSM. No crypto handle while
                                    // provisioned is a wiring bug.
                                    let Some(crypto) = self.hsm_crypto.as_ref() else {
                                        return Err(BackendError::Internal(
                                            "HSM provisioned but no HsmCryptoProvider attached — CEK unwrap requires crypto".into(),
                                        ));
                                    };
                                    let unwrap: std::sync::Arc<
                                        dyn sumo_onboard::decryptor::KeyUnwrap + Send + Sync,
                                    > = std::sync::Arc::new(hsm::HsmKeyUnwrap::from_crypto(
                                        crypto.clone(),
                                        hsm::KeyRole::DeviceDecryption.handle(),
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

        // Bank activation: route through the provider's `activate`, which runs
        // the activator (if any) then records the activation in the boot
        // selector. Read NV.active_bank directly — install_precomputed (above,
        // when it ran) just flipped it to the just-installed bank, which is
        // exactly the bank that has the payloads the activator needs.
        // determine_target_bank() would return the OTHER bank (active.other())
        // on first flash — that's empty and would make the activator fail with
        // "firmware not found". See 2c9d2d8 for the original fix to this race;
        // d25d967 re-introduced the determine_target_bank() call and reopened
        // the bug for first-ever-flash on activator-backed components. For VMs
        // (no activator) `activate` only seals the selector, so this runs
        // unconditionally.
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
            if let Err(e) = self.bank_provider.activate(wrote_to) {
                tracing::error!(
                    bank_set = ?self.bank_set,
                    bank = ?wrote_to,
                    error = %e,
                    "bank activation failed during finalize — rolling back"
                );
                let mut nv = self.nv_write()?;
                let _ = ota::rollback(&mut *nv, self.bank_set);
                return Err(BackendError::Internal(format!(
                    "bank activation failed: {e}"
                )));
            }
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

        // A write-through singleshot that still needs a node reboot (e.g. rt):
        // `committed` stays true, so this reboot-owed bit is the only durable
        // record that "a node reboot is owed" — and it survives a power cycle (or
        // a failed/refused reset), which the in-memory flash state does not. The
        // gate then refuses a new flash node-wide until the reboot runs and the
        // trial is resolved (cleared in commit_flash). Rollbackable (banked)
        // components do NOT mark here: they stage together before one reboot, so
        // it would refuse their own siblings. See docs/design/node-update-state.md.
        if !self.config.supports_rollback
            && self.reset_kind() == machine_mgr::ResetKind::RequiresEcuReset
        {
            self.set_reboot_owed(true)?;
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

    /// Read the entity's runtime status — ISO 17978-3 §7.19.2. Liveness comes
    /// from the guest heartbeat (`ready` = running + a fresh heartbeat; otherwise
    /// `notReady`); non-guest components (no vm-service addr) are present-by-
    /// definition → `ready`. The vendor `x-sumo-runtime` block (§5.4.5) carries
    /// the heartbeat `boot_id` (a per-lifetime nonce — the orchestrator's reboot
    /// witness: a *changed* boot_id proves a fresh guest lifetime, including a
    /// node reboot, which `boot_count` cannot witness), the heartbeat `hb_seq`
    /// (liveness), and `boot_count` (the NV trial counter — a metric, bumped only
    /// by a per-component `ecu_reset`).
    async fn read_entity_status(&self) -> BackendResult<EntityStatusBody> {
        let health = match &self.vm_service_addr {
            Some(socket) => query_vm_health(socket, &self.entity_info.id).await,
            None => None,
        };
        let status = if self.vm_service_addr.is_none()
            || health
                .as_ref()
                .is_some_and(|h| h.status == "running" && h.guest_state == 1)
        {
            EntityStatus::Ready
        } else {
            EntityStatus::NotReady
        };

        let boot_count: u64 = self
            .nv
            .lock()
            .unwrap()
            .read_boot_state()
            .map(|s| s.banks[self.bank_set.as_index()].boot_count as u64)
            .unwrap_or(0);

        let mut runtime = serde_json::Map::new();
        runtime.insert("boot_count".into(), serde_json::json!(boot_count));
        if let Some(h) = &health {
            runtime.insert("hb_seq".into(), serde_json::json!(h.hb_seq));
            // Per-lifetime nonce — changes on every guest (re)boot (node reboot
            // OR per-VM relaunch). The orchestrator's reboot witness: a changed
            // boot_id proves a fresh guest lifetime and can't be faked by a
            // stale heartbeat (which carries the OLD boot_id). Unlike boot_count
            // (bumped only by a per-component ecu_reset), this also witnesses a
            // node reboot.
            runtime.insert("boot_id".into(), serde_json::json!(h.boot_id));
        }
        let mut extensions = serde_json::Map::new();
        extensions.insert("x-sumo-runtime".into(), serde_json::Value::Object(runtime));

        Ok(EntityStatusBody {
            status,
            extensions,
            ..Default::default()
        })
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

        // Was the guest running before this reset? Used ONLY to pick the
        // vm-service "restart" vs "start" intent (a never-started guest
        // shouldn't render as "Shutting Down"). The activation verdict is the
        // orchestrator's job now: it reads `/status` and confirms the guest's
        // heartbeat `boot_id` changed (a fresh lifetime) AND status==ready.
        // The device no longer keeps an in-memory boot_id baseline.
        let was_running = if self.config.single_bank {
            false
        } else {
            match self.vm_service_addr.as_ref() {
                Some(sock) => query_vm_health(sock, &self.entity_info.id).await.is_some(),
                None => false,
            }
        };

        // Advance flash state to Activated — the bank is flipped and the trial
        // is armed. The device reports the NV/bank truth; it no longer does its
        // own in-memory "is the guest healthy" promotion (that was the
        // `verify_baseline_boot_id`/`guest_is_running` path, the source of the
        // original "promoted too soon → commit 404" bug). The orchestrator owns
        // the health verdict now, confirming the guest's heartbeat `boot_id`
        // changed AND status==ready via `/status` before it commits.
        {
            let mut ft = self.flash_transfer.lock().unwrap();
            if let Some(ref mut t) = *ft {
                t.state = FlashState::Activated;
            }
        }

        // Reset session and security (ISO 14229)
        *self.session.lock().unwrap() = SessionState::Default;
        *self.security.lock().unwrap() = SecurityAccessState::default();

        // Bank activation happens at install-finalize (finalize_flash),
        // not here. ecu_reset just transitions the flash state machine.

        // Pick "restart" vs "start" based on whether the guest was actually
        // running pre-reset (the `was_running` probe above). For an offline
        // guest (factory provision, post-crash) the shutdown step is a phantom
        // — vm-service would handle it (NotRunning → fall through to start_vm)
        // but the orchestrator-/GUI-visible intent should be "start", not
        // "restart", so the cluster tile doesn't display "Shutting Down" for a
        // guest that never ran.
        let action = if was_running { "restart" } else { "start" };

        // Notify vm-service to (re)launch the guest on the just-activated bank.
        // The boot selector is the authority for which bank actually boots; we
        // no longer flip a per-component `current` symlink here. We still carry
        // the running bank explicitly so vm-service relaunches THIS bank, not
        // the stale boot-time `def.bank` (the "kernel not found" bug).
        if let Some(ref socket_path) = self.vm_service_addr {
            let target_bank = *self.running_bank.lock().unwrap();
            let id = &self.entity_info.id;
            match Self::notify_vm_service(socket_path, id, action, Some(target_bank)).await {
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

        // The device no longer promotes Verifying→Activated from its own
        // in-memory guest-health check (the retired `guest_is_running` /
        // `verify_baseline_boot_id` path). `ecu_reset` sets Activated directly
        // (bank flipped + trial armed); the orchestrator confirms the guest is
        // actually healthy via `/status` (boot_id changed + ready).
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
                .and_then(|id| id.version)
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
        // NV commit routed through the bank provider (it folds AlreadyCommitted
        // into Ok for CRL / idempotent commits). The provider writes NV with a
        // plain lock, so refresh the DID cache afterwards — the `nv_write()`
        // guard used to do this on drop, and the served identity/manifest must
        // reflect the just-committed bank.
        self.bank_provider
            .commit()
            .map_err(|e| BackendError::Internal(e.to_string()))?;
        // Trial resolved — return the node toward Idle (clear reboot-owed + drop
        // from staging). Shared with rollback_flash via resolve_node_transaction.
        self.resolve_node_transaction()?;
        {
            let nv = self
                .nv
                .lock()
                .map_err(|_| BackendError::Internal("nv lock poisoned".into()))?;
            self.refresh_did_cache_locked(&nv);
        }

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
        // NV rollback routed through the bank provider. Refresh the DID cache
        // afterwards (the provider writes NV with a plain lock; the old
        // `nv_write()` guard refreshed on drop).
        self.bank_provider
            .rollback()
            .map_err(|e| BackendError::Internal(e.to_string()))?;
        // Transaction resolved (reverted) — return the node toward Idle, same as
        // commit. Without this a rolled-back banked component stays in the
        // coordinator's staging and the node never leaves Staging/Trial.
        self.resolve_node_transaction()?;
        {
            let nv = self
                .nv
                .lock()
                .map_err(|_| BackendError::Internal("nv lock poisoned".into()))?;
            self.refresh_did_cache_locked(&nv);
        }
        // Clear flash transfer state after rollback
        *self.flash_transfer.lock().unwrap() = None;
        Ok(())
    }

    async fn abort_flash(&self, _transfer_id: &str) -> BackendResult<()> {
        // Mirror `ComponentAdapter::abort_install` exactly — the round-trip the
        // directly-wired bank/hsm engine no longer goes through. Pre-finalize
        // abort is always allowed: drop the staging session (the same shared
        // `clear_flash_session` the adapter calls). Post-finalize the bank
        // pointer has already flipped to the next-boot bank and the engine
        // can't unflip it, so refuse rather than silently no-op — surfaced as
        // `InvalidRequest`, the exact wire mapping `map_machine_error` produces
        // from the adapter's `PolicyRejected`, so the direct (bank/hsm) and
        // routed (vm2/app) abort paths return identical HTTP.
        if self.flash_is_finalized() {
            return Err(BackendError::InvalidRequest(
                "cannot abort: install already finalized".into(),
            ));
        }
        self.clear_flash_session();
        // The gate staged this component at start_flash; an abort is a terminal
        // resolution too, so drop it from the coordinator's staging (return the
        // node toward Idle). reboot-owed clear is a no-op here — abort is rejected
        // post-finalize above, so nothing was ever marked.
        self.resolve_node_transaction()?;
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
            let s = ComponentBackend::<nv_store::block::MemBlockDevice>::nv_bytes_to_string(value);
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

/// The SW-identity DIDs (subset of the F187–F19E range) sourced ONLY from the
/// running bank's signed IVD manifest — never from NV. These are exactly the
/// DIDs `identity_to_did_bytes` overlays into `did_cache`, so they read back
/// (and may be listed) only when `verified_bank_manifest` finds a committed
/// manifest. The other F18x/F19x DIDs in `DID_REGISTRY` (supplier_id F18A,
/// manufacturing_date F18B, serial_number F18C, vin F190, ecu_hw_number F191,
/// supplier_hw_number F192, supplier_hw_version F193) are HARDWARE identity
/// read from the NV Factory blob regardless of any manifest — they are NOT
/// here and stay listed unconditionally.
pub(crate) const IDENTITY_DIDS: [u16; 9] = [
    did::DID_SPARE_PART_NUMBER,
    did::DID_ECU_SW_NUMBER,
    did::DID_FW_VERSION,
    did::DID_SUPPLIER_SW_NUMBER,
    did::DID_SUPPLIER_SW_VERSION,
    did::DID_SYSTEM_NAME,
    did::DID_TESTER_SERIAL,
    did::DID_PROGRAMMING_DATE,
    did::DID_ODX_FILE_ID,
];

/// Whether `did` is a manifest-sourced SW-identity DID (see [`IDENTITY_DIDS`]).
pub(crate) fn is_identity_did(did: u16) -> bool {
    IDENTITY_DIDS.contains(&did)
}

/// Convert a [`FirmwareIdentity`] into the `(did, bytes)` pairs for the 9
/// SW-identity DIDs, each rendered in the historical fixed-width UDS byte
/// form (UTF-8, NUL-padded / truncated to the width that DID used when it
/// lived in NvFwMeta — 32 bytes, except programming_date's 8). Absent
/// (`None` / empty) identity fields are skipped (DID stays not-found), so a
/// blank manifest identity behaves like an unprovisioned field.
fn identity_to_did_bytes(identity: &FirmwareIdentity) -> Vec<(u16, Vec<u8>)> {
    /// Pad/truncate a UTF-8 string to `width` bytes, NUL-padded — the
    /// same fixed-width form `read_did` used to return from NvFwMeta.
    fn fixed(s: &str, width: usize) -> Vec<u8> {
        let mut buf = vec![0u8; width];
        let n = s.len().min(width);
        buf[..n].copy_from_slice(&s.as_bytes()[..n]);
        buf
    }

    // (did, value, field-width). `version` → F189, `system_name` → F197.
    let fields: [(u16, &Option<String>, usize); 9] = [
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
        .filter_map(|(did, s, width)| {
            s.as_deref()
                .filter(|v| !v.is_empty())
                .map(|v| (*did, fixed(v, *width)))
        })
        .collect()
}

/// Render the installed firmware as the `x-sumo-installed-manifest` JSON
/// body: the signed identity + per-file `(path, sha256-hex)` inventory + the
/// base64 of the raw signature and manifest bytes (so a SW-mapping tool can
/// re-verify the device signature independently).
///
/// IVD-specific scalar fields (`ivd_version`, `signed_at_unix`) aren't part
/// of the kind-agnostic [`InstalledFirmware`], so they're decoded back out of
/// the raw signed CBOR here — this is component-mgr's IVD serving path, which is
/// allowed to know the IVD wire (`fw.raw` is exactly those CBOR bytes).
fn installed_manifest_json(fw: &InstalledFirmware) -> serde_json::Value {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;

    // Render an identity field exactly as before — the IVD manifest stored
    // readable strings (empty for absent), so map `None` back to "".
    fn s(o: &Option<String>) -> &str {
        o.as_deref().unwrap_or("")
    }

    let files: Vec<serde_json::Value> = fw
        .files
        .iter()
        .map(|f| {
            serde_json::json!({
                "path": f.name,
                "sha256": hex::encode(f.sha256),
            })
        })
        .collect();

    // Recover the two IVD-only scalars from the signed CBOR. Absent / undecodable
    // raw (non-IVD kinds) falls back to the manifest version + 0.
    let (ivd_version, signed_at_unix) = fw
        .raw
        .as_deref()
        .and_then(|b| hsm::ivd::decode_manifest(b).ok())
        .map(|m| (m.ivd_version, m.signed_at_unix))
        .unwrap_or((hsm::ivd::IVD_MANIFEST_VERSION, 0));

    serde_json::json!({
        "ivd_version": ivd_version,
        "gen": fw.gen,
        "signed_at_unix": signed_at_unix,
        "identity": {
            "name": s(&fw.identity.name),
            "version": s(&fw.identity.version),
            "ecu_sw_number": s(&fw.identity.ecu_sw_number),
            "supplier_sw_number": s(&fw.identity.supplier_sw_number),
            "supplier_sw_version": s(&fw.identity.supplier_sw_version),
            "spare_part_number": s(&fw.identity.spare_part_number),
            "odx_file_id": s(&fw.identity.odx_file_id),
            "system_name": s(&fw.identity.system_name),
            "programming_date": s(&fw.identity.programming_date),
            "tester_serial": s(&fw.identity.tester_serial),
        },
        "files": files,
        "signature_b64": b64.encode(fw.signature.as_deref().unwrap_or(&[])),
        "manifest_b64": b64.encode(fw.raw.as_deref().unwrap_or(&[])),
    })
}

// `bank_dir_is_payload_empty` + `bank_dir_name` moved to
// `crate::bank_provider` alongside the IVD bank-layout logic that uses
// them — the engine no longer touches bank dirs directly, it routes
// every write through `BankProvider::open_payload_writer`.
// `bank_set_dir_name` / `bank_file_names` / `payload_target_name`
// retired earlier — per-slot behavior lives on `BankSetSpec` in
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
    /// Random per-guest-lifetime id from the heartbeat wire format. Surfaced in
    /// `/status` `x-sumo-runtime.boot_id` — the orchestrator's reboot witness: a
    /// *changed* boot_id confirms a fresh post-reset lifetime, not stale shmem
    /// from the previous one (qvm-shmem regions persist across stop/start).
    pub boot_id: u32,
    /// Coarse health status string ("running" / "stopped" / "unhealthy").
    /// ComponentBackend treats anything not "running" as not-yet-activated —
    /// captures the stale-heartbeat case (vm-service flips to
    /// "unhealthy" after 5s of stuck seq) without duplicating that
    /// timeout here.
    pub status: String,
}

/// Synthesise a [`GuestHealth`] snapshot for a component that has no
/// vm-service backing (e.g. activator-backed components like RT/M7).
/// Called from `ComponentBackend::read_data` when `vm_service_addr` is None.
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
/// **Async** intentionally: `component-mgr` runs on the same tokio runtime as
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
    use std::path::Path;

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
    fn provisioned_hsm(
        tag: &str,
    ) -> (
        Arc<Mutex<dyn hsm::HsmProvider>>,
        Arc<dyn hsm::HsmCryptoProvider>,
        PathBuf,
    ) {
        use hsm::payload::*;
        let keystore = std::env::temp_dir().join(format!("component-mgr-identity-ks-{tag}"));
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
            certificates: Vec::new(),
            trust_anchors: Vec::new(),
        };
        hsm.write_keystore(&ks).unwrap();
        hsm.ensure_device_keys().unwrap();
        std::fs::write(keystore.join("provision_state"), b"1\n").unwrap();
        assert!(hsm.is_provisioned().unwrap());

        // A second SimHsm over the same keystore is the crypto handle (IVD
        // sign/verify); the first SimHsm is the provisioning-authority provider.
        let crypto: Arc<dyn hsm::HsmCryptoProvider> = Arc::new(SimHsm::new(
            PathBuf::from("/dev/null"),
            keystore.clone(),
            5400,
        ));
        (Arc::new(Mutex::new(hsm)), crypto, keystore)
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

    /// Construct a ComponentBackend (vm1) with images_dir + provisioned HSM,
    /// inject a Verified package carrying `meta`, and point the flash
    /// transfer at it so `ivd_sign_staged_bank` picks up its identity.
    fn backend_with_package(
        tag: &str,
        meta: ImageMeta,
    ) -> (ComponentBackend<MemBlockDevice>, PathBuf, PathBuf) {
        let images_dir = std::env::temp_dir().join(format!("component-mgr-identity-img-{tag}"));
        let _ = std::fs::remove_dir_all(&images_dir);
        std::fs::create_dir_all(&images_dir).unwrap();

        let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
        let mut boot = NvBootState::default();
        nv.write_boot_state(&mut boot).unwrap();
        let nv = Arc::new(Mutex::new(nv));

        let (hsm, crypto, keystore) = provisioned_hsm(tag);

        let backend = ComponentBackend::with_options(
            BankSet::Vm1,
            nv,
            Arc::new(NoopManifest),
            Arc::new(NoopSecurity),
            ComponentConfig::default(),
            None,
            Some(images_dir.clone()),
            Some(hsm),
        )
        .with_hsm_crypto(crypto);

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

        // read_installed's identity must round-trip exactly what ImageMeta
        // projected (now mapped to the kind-agnostic FirmwareIdentity).
        let id = backend.verified_bank_identity(Bank::B).unwrap();
        assert_eq!(id.version.as_deref(), Some("1.2.0"));
        assert_eq!(id.ecu_sw_number.as_deref(), Some("VM1-SW-001"));
        assert_eq!(id.system_name.as_deref(), Some("VM1-Linux"));
        assert_eq!(id.spare_part_number.as_deref(), Some("VM1-SPARE-001"));
        assert_eq!(id.supplier_sw_number.as_deref(), Some("SUP-SW-VM1-001"));
        assert_eq!(id.odx_file_id.as_deref(), Some("ODX-VM1-V1"));

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
    fn tampered_manifest_identity_is_reported_report_only() {
        // Report-only diagnostic read: the identity DIDs come from the on-disk
        // signed manifest WITHOUT an HSM verify, so a tampered-but-decodable
        // manifest is still reported. The served object carries the signature +
        // bytes for the client to verify; the real gate is `verify_bank`.
        let (backend, images_dir, keystore) = backend_with_package("tamper", sample_image_meta());
        backend.ivd_sign_staged_bank(Bank::B).unwrap();

        // Flip a byte INSIDE a string value (the manifest's last field is the
        // identity map; the final byte is string content, so it stays
        // structurally decodable) — the signature no longer matches.
        let mpath = images_dir
            .join("vm1")
            .join("bank_b")
            .join(hsm::ivd::IVD_MANIFEST_FILE);
        let mut bytes = std::fs::read(&mpath).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&mpath, &bytes).unwrap();

        // Report-only: the identity is still served (it decodes).
        assert!(
            backend.verified_bank_identity(Bank::B).is_some(),
            "report-only path serves a decodable manifest's identity"
        );
        assert!(!backend.identity_did_bytes(Bank::B).is_empty());

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

        // C-031: with a committed manifest the F187–F19E SW-identity DIDs are
        // listed (they read back from the manifest overlay) AND read 200 — so
        // list and read agree on a flashed bank. fw_version (F189) stands in.
        // Refresh the cache the way the real flash flow does (every
        // finalize/commit/ecu_reset NV write triggers `NvWriteGuard::drop`),
        // since this test signs the bank directly without an NV write.
        {
            let nv = backend.nv.lock().unwrap();
            backend.refresh_did_cache_locked(&nv);
        }
        let fw = params
            .iter()
            .find(|p| p.id == "fw_version")
            .expect("fw_version must be listed when a manifest exists");
        assert_eq!(fw.did.as_deref(), Some("F189"));
        let read = backend
            .read_data(&["fw_version".to_string()])
            .await
            .expect("listed identity DID must read back");
        assert_eq!(read[0].value, serde_json::json!("1.2.0"));

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
        let ok = hsm::HsmCryptoProvider::verify(
            &**backend.hsm_crypto.as_ref().unwrap(),
            hsm::KeyRole::IvdSigning.handle(),
            &mbytes,
            &sig,
        )
        .unwrap();
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

        // C-031: the manifest-sourced SW-identity DIDs are likewise absent
        // (they'd 404 on read), while a hardware/factory DID stays listed.
        assert!(
            !params.iter().any(|p| is_identity_did(
                u16::from_str_radix(p.did.as_deref().unwrap_or(""), 16).unwrap_or(0)
            )),
            "no manifest-gated identity DID may be listed without a committed manifest"
        );
        assert!(
            params.iter().any(|p| p.id == "serial_number"),
            "hardware/factory serial_number must remain listed without a manifest"
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
    async fn installed_manifest_param_reports_even_when_signature_would_not_verify() {
        // Report-only path: the diagnostic read surfaces what the bank is
        // supposed to have installed and hands the client the raw bytes +
        // signature to verify independently. It does NOT call into the HSM, so
        // a manifest whose signature would FAIL an HSM verify (here: a flipped
        // byte) is still served — the served `manifest_b64` carries the exact
        // tampered on-disk bytes so a `--pubkey` client catches the mismatch
        // itself. The real on-device gate stays in `verify_bank`.
        let (backend, images_dir, keystore) =
            backend_with_package("ivdtamper", sample_image_meta());
        *backend.running_bank.lock().unwrap() = Bank::B;
        backend.ivd_sign_staged_bank(Bank::B).unwrap();

        // Flip a byte inside the signed manifest CBOR — still structurally
        // decodable, but the signature no longer matches it.
        let mpath = images_dir
            .join("vm1")
            .join("bank_b")
            .join(hsm::ivd::IVD_MANIFEST_FILE);
        let mut bytes = std::fs::read(&mpath).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&mpath, &bytes).unwrap();

        // Invalidate the cache (an NV write would normally do this) so the
        // re-read hits disk and sees the tampered bytes.
        {
            let nv = backend.nv.lock().unwrap();
            backend.refresh_did_cache_locked(&nv);
        }

        // It is still listed (report-only — present + decodable).
        let params = backend.list_parameters().await.unwrap();
        assert!(
            params.iter().any(|p| p.id == INSTALLED_MANIFEST_PARAM_ID),
            "report-only: param advertised whenever the manifest decodes"
        );

        // And it is served — NOT 404'd.
        let vals = backend
            .read_data(&[INSTALLED_MANIFEST_PARAM_ID.to_string()])
            .await
            .expect("report-only read must succeed even with a bad signature");
        assert_eq!(vals.len(), 1);
        let v = &vals[0].value;

        // The served manifest_b64 is exactly the tampered on-disk bytes — the
        // client re-verifies these against `--pubkey` and detects the tamper.
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let mbytes = b64
            .decode(v["manifest_b64"].as_str().unwrap())
            .expect("manifest_b64 decodes");
        let on_disk = std::fs::read(&mpath).unwrap();
        assert_eq!(
            mbytes, on_disk,
            "served bytes are the raw on-disk (tampered) manifest"
        );
        // Prove the HSM verify over the served artefacts now FAILS — i.e. the
        // client's independent check would reject it.
        let sig = b64
            .decode(v["signature_b64"].as_str().unwrap())
            .expect("signature_b64 decodes");
        let ok = hsm::HsmCryptoProvider::verify(
            &**backend.hsm_crypto.as_ref().unwrap(),
            hsm::KeyRole::IvdSigning.handle(),
            &mbytes,
            &sig,
        )
        .unwrap();
        assert!(
            !ok,
            "served (tampered) bytes must NOT verify — the client gate catches it"
        );

        cleanup(&images_dir, &keystore);
    }

    /// A `BankActivator` that always fails — drives the finalize rollback path.
    struct FailingActivator;
    impl machine_mgr::BankActivator for FailingActivator {
        fn activate(
            &self,
            _bank_dir: &Path,
        ) -> Result<(), machine_mgr::bank_activator::BankActivatorError> {
            Err(machine_mgr::bank_activator::BankActivatorError::Failed(
                "synthetic activation failure".into(),
            ))
        }
    }

    /// When the bank provider's `activate` fails during finalize (the activator
    /// errors), the engine must (a) surface the error and (b) roll NV back to
    /// the previously-committed bank. The activator runs before the boot
    /// selector is sealed, so a failure leaves the activation un-recorded.
    #[tokio::test]
    async fn finalize_activation_failure_rolls_back() {
        let images_dir = std::env::temp_dir().join("component-mgr-activate-fail-img");
        let _ = std::fs::remove_dir_all(&images_dir);
        std::fs::create_dir_all(&images_dir).unwrap();

        // NV in the post-install trial state: active_bank flipped to B,
        // committed=false (exactly what `install_precomputed` leaves behind).
        let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
        let mut boot = NvBootState::default();
        let idx = BankSet::Vm1.as_index();
        boot.banks[idx].active_bank = Bank::B;
        boot.banks[idx].committed = false;
        nv.write_boot_state(&mut boot).unwrap();
        let nv = Arc::new(Mutex::new(nv));

        // Stage payloads in bank_b (the just-installed bank).
        let set_dir = images_dir.join("vm1");
        let bank_b = set_dir.join("bank_b");
        std::fs::create_dir_all(&bank_b).unwrap();
        std::fs::write(bank_b.join("rootfs.img"), b"new bank bytes").unwrap();

        let backend = ComponentBackend::with_options(
            BankSet::Vm1,
            nv.clone(),
            Arc::new(NoopManifest),
            Arc::new(NoopSecurity),
            ComponentConfig::default(),
            None,
            Some(images_dir.clone()),
            None,
        )
        .with_bank_activator(Arc::new(FailingActivator));

        // (a) finalize must surface the activation failure.
        let err = backend.finalize_flash().await.unwrap_err();
        assert!(
            err.to_string().contains("bank activation failed"),
            "expected activation-failure error, got: {err}"
        );

        // (b) NV rolled back to the previously-committed bank (A), committed.
        {
            let nv_guard = nv.lock().unwrap();
            let state = nv_guard.read_boot_state().unwrap();
            assert_eq!(
                state.banks[idx].active_bank,
                Bank::A,
                "NV active_bank must roll back to A after failed activation"
            );
            assert!(
                state.banks[idx].committed,
                "rollback must leave the bank committed"
            );
        }

        let _ = std::fs::remove_dir_all(&images_dir);
    }

    /// B5 regression: a flash that lands on the session-less *legacy* path while
    /// the bank set is in trial mode must be refused (`Busy`) *before* it touches
    /// any bank — it must never wipe the committed rollback bank. Without the
    /// `ensure_flash_can_start()` guard in the legacy branch of
    /// `receive_package_stream`, the path resolved the target to the committed
    /// bank (`active.other()`) and `prepare_target_bank_dir` wiped it.
    #[tokio::test]
    async fn legacy_upload_in_trial_is_refused_without_wiping_committed_bank() {
        let images_dir = std::env::temp_dir().join("component-mgr-b5-trial-legacy-img");
        let _ = std::fs::remove_dir_all(&images_dir);
        std::fs::create_dir_all(&images_dir).unwrap();

        // Trial state: active=B, committed=false → the committed (rollback) bank
        // is A = active.other(), which the buggy legacy path would target+wipe.
        let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
        let mut boot = NvBootState::default();
        let idx = BankSet::Vm1.as_index();
        boot.banks[idx].active_bank = Bank::B;
        boot.banks[idx].committed = false;
        nv.write_boot_state(&mut boot).unwrap();
        let nv = Arc::new(Mutex::new(nv));

        // Sentinel in the committed bank (A) that must survive.
        let bank_a = images_dir.join("vm1").join("bank_a");
        std::fs::create_dir_all(&bank_a).unwrap();
        let sentinel = bank_a.join("rootfs.img");
        std::fs::write(&sentinel, b"committed rollback bytes").unwrap();

        let backend = ComponentBackend::with_options(
            BankSet::Vm1,
            nv,
            Arc::new(NoopManifest),
            Arc::new(NoopSecurity),
            ComponentConfig::default(),
            None,
            Some(images_dir.clone()),
            None,
        );

        // No flash session → session-less legacy branch. The guard fires before
        // the stream is read, so an empty stream is sufficient.
        let stream: PackageStream = Box::pin(futures::stream::iter(Vec::<
            Result<bytes::Bytes, Box<dyn std::error::Error + Send + Sync>>,
        >::new()));
        let err = backend
            .receive_package_stream(stream, None)
            .await
            .expect_err("legacy upload in trial mode must be refused");
        assert!(
            matches!(err, BackendError::Busy(_)),
            "expected Busy (trial mode), got: {err:?}"
        );

        // The committed rollback bank must be untouched.
        assert!(
            sentinel.exists(),
            "committed bank A must NOT be wiped by a refused trial-mode flash"
        );
        assert_eq!(
            std::fs::read(&sentinel).unwrap(),
            b"committed rollback bytes",
            "committed bank contents must be intact"
        );

        let _ = std::fs::remove_dir_all(&images_dir);
    }
}

#[cfg(test)]
mod bank_provider_injection_tests {
    use super::*;
    use crate::manifest_provider::ManifestError;
    use machine_mgr::bank_provider::{BankError, BankProvider};
    use machine_mgr::ResetKind;
    use nv_store::block::MemBlockDevice;
    use nv_store::store::MIN_NV_DEVICE_SIZE;

    struct NoopManifest;
    impl ManifestProvider for NoopManifest {
        fn validate(&self, _d: &[u8], _m: u32) -> Result<ValidatedFirmware, ManifestError> {
            Err(ManifestError::ParseError("unused".into()))
        }
    }
    struct NoopSecurity;
    impl SecurityProvider for NoopSecurity {
        fn generate_seed(&self, _component: BankSet, _level: u8) -> Vec<u8> {
            Vec::new()
        }
        fn validate_key(&self, _c: BankSet, _l: u8, _s: &[u8], _k: &[u8]) -> bool {
            true
        }
    }

    /// A sentinel `BankProvider` whose `reset_kind()` is the distinctive
    /// `RequiresEcuReset` — the default `IvdBankProvider` (no activator) returns
    /// `Local`, so observing `RequiresEcuReset` through `ComponentBackend`
    /// proves the injected provider is the one in use. Every other method is an
    /// unreachable stub: the test only exercises the dispatch.
    struct SentinelProvider;
    impl BankProvider for SentinelProvider {
        fn active_bank(&self) -> Bank {
            Bank::B
        }
        fn target_bank(&self) -> Bank {
            Bank::A
        }
        fn prepare_target(&self, _bank: Bank) -> Result<(), BankError> {
            Ok(())
        }
        fn open_payload_writer(
            &self,
            _bank: Bank,
            _name: &str,
        ) -> Result<Box<dyn std::io::Write + Send>, BankError> {
            Err(BankError::Failed("sentinel".into()))
        }
        fn seal(&self, _b: Bank, _i: FirmwareIdentity, _g: u64) -> Result<(), BankError> {
            Ok(())
        }
        fn read_installed(&self, _bank: Bank) -> Result<InstalledFirmware, BankError> {
            Err(BankError::NotInstalled)
        }
        fn verify_payload(&self, _b: Bank, _n: &str, _s: &[u8; 32]) -> Result<(), BankError> {
            Ok(())
        }
        fn activate(&self, _bank: Bank) -> Result<ResetKind, BankError> {
            Ok(ResetKind::RequiresEcuReset)
        }
        fn commit(&self) -> Result<(), BankError> {
            Ok(())
        }
        fn rollback(&self) -> Result<(), BankError> {
            Ok(())
        }
        fn reset_kind(&self) -> ResetKind {
            ResetKind::RequiresEcuReset
        }
    }

    fn backend() -> ComponentBackend<MemBlockDevice> {
        let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
        let mut boot = NvBootState::default();
        nv.write_boot_state(&mut boot).unwrap();
        ComponentBackend::with_options(
            BankSet::Vm1,
            Arc::new(Mutex::new(nv)),
            Arc::new(NoopManifest),
            Arc::new(NoopSecurity),
            ComponentConfig::default(),
            None,
            None,
            None,
        )
    }

    /// Single-bank (HSM-style), irreversible backend for update-mode tests.
    fn singleshot_backend() -> ComponentBackend<MemBlockDevice> {
        let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
        let mut boot = NvBootState::default();
        nv.write_boot_state(&mut boot).unwrap();
        ComponentBackend::with_options(
            BankSet::Hsm,
            Arc::new(Mutex::new(nv)),
            Arc::new(NoopManifest),
            Arc::new(NoopSecurity),
            ComponentConfig {
                supports_rollback: false,
                single_bank: true,
                entity_type: "hsm".to_string(),
            },
            None,
            None,
            None,
        )
    }

    #[test]
    fn reboot_owed_round_trips_through_nv() {
        // The step-3 durable marker: set/clear this component's node reboot-owed
        // bit and read it back via the same NvUpdateSession record the gate
        // consults. (The refuse-on-RebootPending decision is covered by
        // machine-mgr's node_update tests; this proves the component-mgr NV plumbing.)
        let b = backend(); // BankSet::Vm1
        assert!(b.node_reboot_owed().unwrap().reboot_owed.is_empty());

        b.set_reboot_owed(true).unwrap();
        assert_eq!(
            b.node_reboot_owed().unwrap().reboot_owed,
            vec![format!("bank-set {}", BankSet::Vm1.as_index())]
        );

        b.set_reboot_owed(false).unwrap();
        assert!(b.node_reboot_owed().unwrap().reboot_owed.is_empty());
    }

    #[test]
    fn commit_and_rollback_share_one_resolve_hook() {
        // Regression for the asymmetry saka caught: commit_flash cleared the node
        // transaction but rollback_flash did not, so a rolled-back banked component
        // stayed wedged in Staging/RebootPending and the node never returned to
        // Idle. Both paths now route through `resolve_node_transaction`; this proves
        // the hook clears the durable reboot-owed bit AND drops the component from
        // the coordinator's staging.
        let coord = Arc::new(machine_mgr::node_update::NodeCoordinator::new(vec![(
            BankSet::Vm1.as_index(),
            "vm1".to_string(),
        )]));
        let b = backend().with_node_coordinator(coord.clone());
        let id = b.entity_info().id.clone();

        // Stage it (what start_flash's gate does) + mark a reboot owed (finalize).
        coord
            .gate_new_session([0u8; 32], &id, &b.node_reboot_owed().unwrap(), &[])
            .unwrap();
        b.set_reboot_owed(true).unwrap();
        let d = b.node_reboot_owed().unwrap();
        assert_eq!(
            coord.node_update_state(&d, &[]).phase.as_str(),
            "RebootPending"
        );

        // The single hook both commit_flash and rollback_flash call.
        b.resolve_node_transaction().unwrap();

        let d = b.node_reboot_owed().unwrap();
        assert!(d.reboot_owed.is_empty(), "reboot-owed must be cleared");
        assert_eq!(
            coord.node_update_state(&d, &[]).phase.as_str(),
            "Idle",
            "staging must be cleared -> node Idle"
        );
    }

    #[tokio::test]
    async fn update_mode_param_banked_for_default_component() {
        // Default backend: dual-bank VM, NO firmware flashed. The vendor param
        // is advertised + readable unconditionally (stable config), proving it
        // works pre-flash — unlike x-sumo-installed-manifest which 404s.
        let b = backend();
        let params = b.list_parameters().await.unwrap();
        let p = params
            .iter()
            .find(|p| p.id == UPDATE_MODE_PARAM_ID)
            .expect("x-sumo-update-mode must be listed even with no committed manifest");
        assert!(p.read_only);
        assert!(p.did.is_none());

        let vals = b
            .read_data(&[UPDATE_MODE_PARAM_ID.to_string()])
            .await
            .expect("update-mode reads 200 pre-flash");
        let v = &vals[0].value;
        assert_eq!(v["update_mode"], serde_json::json!("banked"));
        assert_eq!(v["supports_rollback"], serde_json::json!(true));
        assert_eq!(v["dual_bank"], serde_json::json!(true));
    }

    #[tokio::test]
    async fn update_mode_param_singleshot_for_hsm_component() {
        // The HSM keystore is single-bank + irreversible — it must report
        // singleshot / supports_rollback=false so the offboard guard can keep it
        // out of a rollbackable campaign.
        let b = singleshot_backend();
        let params = b.list_parameters().await.unwrap();
        assert!(
            params.iter().any(|p| p.id == UPDATE_MODE_PARAM_ID),
            "x-sumo-update-mode must be listed for the HSM component too"
        );
        let vals = b
            .read_data(&[UPDATE_MODE_PARAM_ID.to_string()])
            .await
            .unwrap();
        let v = &vals[0].value;
        assert_eq!(v["update_mode"], serde_json::json!("singleshot"));
        assert_eq!(v["supports_rollback"], serde_json::json!(false));
        assert_eq!(v["dual_bank"], serde_json::json!(false));
    }

    #[test]
    fn injected_provider_is_the_one_backend_uses() {
        // Default backend: IvdBankProvider with no activator => Local.
        let b = backend();
        assert_eq!(b.reset_kind(), ResetKind::Local);

        // After injection, the backend routes through the sentinel.
        let b = b.with_bank_provider(Arc::new(SentinelProvider));
        assert_eq!(
            b.reset_kind(),
            ResetKind::RequiresEcuReset,
            "reset_kind() must come from the injected provider"
        );
    }

    #[test]
    fn override_survives_later_rebuild_triggering_builders() {
        // with_bank_spec / with_bank_activator call rebuild_bank_provider; the
        // override flag must make those no-op on the provider so the injected
        // one is NOT clobbered.
        let b = backend()
            .with_bank_provider(Arc::new(SentinelProvider))
            .with_bank_spec(crate::bank_spec::BankSetSpec::for_well_known(BankSet::Vm1));
        assert_eq!(
            b.reset_kind(),
            ResetKind::RequiresEcuReset,
            "with_bank_spec after with_bank_provider must not clobber the override"
        );

        struct DummyActivator;
        impl machine_mgr::BankActivator for DummyActivator {
            fn activate(
                &self,
                _d: &std::path::Path,
            ) -> Result<(), machine_mgr::BankActivatorError> {
                Ok(())
            }
        }
        let b = b.with_bank_activator(Arc::new(DummyActivator));
        assert_eq!(
            b.reset_kind(),
            ResetKind::RequiresEcuReset,
            "with_bank_activator after with_bank_provider must not clobber the override"
        );
    }
}

#[cfg(test)]
mod notify_query_tests {
    use super::*;
    use nv_store::block::MemBlockDevice;

    /// The `?bank=` suffix carried to vm-service after an OTA flip. `notify_vm_service`
    /// itself needs a live socket, so the URL-building is factored here and tested pure.
    #[test]
    fn bank_query_maps_each_bank() {
        type Cb = ComponentBackend<MemBlockDevice>;
        assert_eq!(Cb::bank_query(Some(Bank::A)), "?bank=a");
        assert_eq!(Cb::bank_query(Some(Bank::B)), "?bank=b");
        assert_eq!(Cb::bank_query(None), "");
    }
}

#[cfg(test)]
mod abort_flash_tests {
    //! `DiagnosticBackend::abort_flash` on the directly-wired engine
    //! (bank/hsm). Restores the pre-convergence semantics the round-trip
    //! `ComponentAdapter::abort_install` used to provide: Ok pre-finalize,
    //! refusal post-finalize. The routed (vm2/app) abort path is covered in
    //! `install_router_diag_tests`.
    use super::*;
    use crate::manifest_provider::ManifestError;
    use nv_store::block::MemBlockDevice;
    use nv_store::store::MIN_NV_DEVICE_SIZE;

    struct NoopManifest;
    impl ManifestProvider for NoopManifest {
        fn validate(&self, _d: &[u8], _m: u32) -> Result<ValidatedFirmware, ManifestError> {
            Err(ManifestError::ParseError("unused".into()))
        }
    }
    struct NoopSecurity;
    impl SecurityProvider for NoopSecurity {
        fn generate_seed(&self, _component: BankSet, _level: u8) -> Vec<u8> {
            Vec::new()
        }
        fn validate_key(&self, _c: BankSet, _l: u8, _s: &[u8], _k: &[u8]) -> bool {
            true
        }
    }

    fn backend() -> ComponentBackend<MemBlockDevice> {
        let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
        let mut boot = NvBootState::default();
        nv.write_boot_state(&mut boot).unwrap();
        ComponentBackend::with_options(
            BankSet::Vm1,
            Arc::new(Mutex::new(nv)),
            Arc::new(NoopManifest),
            Arc::new(NoopSecurity),
            ComponentConfig::default(),
            None,
            None,
            None,
        )
    }

    /// Seed a flash transfer in `state` so `flash_is_finalized()` reflects it.
    fn set_transfer_state(b: &ComponentBackend<MemBlockDevice>, state: FlashState) {
        *b.flash_transfer.lock().unwrap() = Some(FlashTransferState {
            transfer_id: "t1".into(),
            package_id: "pkg-1".into(),
            state,
            image_size: 0,
            streamed_files: Vec::new(),
        });
    }

    #[tokio::test]
    async fn abort_flash_ok_when_no_session() {
        // No session in flight — abort is an idempotent success (mirrors
        // ComponentAdapter::abort_install on a fresh backend).
        let b = backend();
        assert!(!b.flash_is_finalized());
        b.abort_flash("nope").await.unwrap();
    }

    #[tokio::test]
    async fn abort_flash_ok_pre_finalize_clears_session() {
        // A staged-but-not-finalized session (AwaitingActivation) aborts Ok and
        // the staging state is dropped.
        let b = backend();
        *b.flash_session.lock().unwrap() = Some(FlashSessionState::Complete);
        set_transfer_state(&b, FlashState::AwaitingActivation);
        assert!(!b.flash_is_finalized());

        b.abort_flash("t1").await.unwrap();

        assert!(b.flash_session.lock().unwrap().is_none());
        assert!(b.flash_transfer.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn abort_flash_rejected_post_finalize() {
        // Post-finalize (bank pointer already flipped) abort must refuse — the
        // engine can't unflip it. Surfaced as InvalidRequest (HTTP 400), the
        // exact wire mapping `map_machine_error` produces from the adapter's
        // PolicyRejected, so direct and routed abort paths agree.
        for st in [
            FlashState::AwaitingReboot,
            FlashState::Activated,
            FlashState::Committed,
            FlashState::RolledBack,
        ] {
            let b = backend();
            set_transfer_state(&b, st);
            assert!(b.flash_is_finalized(), "{st:?} should be finalized");

            let err = b.abort_flash("t1").await.unwrap_err();
            assert!(
                matches!(err, BackendError::InvalidRequest(_)),
                "{st:?}: expected InvalidRequest, got {err:?}"
            );
            assert_eq!(err.status_code(), 400, "{st:?}");
            // Refused → the finalized transfer is left intact, not cleared.
            assert!(b.flash_transfer.lock().unwrap().is_some(), "{st:?}");
        }
    }
}
