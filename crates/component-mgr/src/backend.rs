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
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
// `OnceLock` caches the process-wide boot_epoch (read+bumped once at first
// paged-log request); `Path`/`BTreeMap` back the reboot-safe log cursor below.
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::OnceLock;

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

/// Vendor SOVD operation id for **attest-time**: push a SoftwareAuthority-signed
/// SUIT manifest so the device ratchets its safe-time floor from the manifest's
/// signed (protected-header) `signing_time`. Lets an operator advance a
/// clock-lagging device's trusted-time floor BEFORE a flash, so a freshly-minted
/// delegate cert (`not_before ≈ now`) validates against `max(wall_clock, floor)`
/// (`docs/safe-time-floor.md`). Verify-only: no payload, no bank touch; monotonic,
/// so an older-than-floor manifest is a harmless no-op. Device-global — advertised
/// on the host/device component (the floor + clock are shared singletons).
pub const ATTEST_TIME_OP_ID: &str = "x-sumo-attest-time";

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

/// Where this component's logs come from — drives SOVD §7.21
/// `GET /components/{id}/logs`. `None` (the default) keeps
/// `capabilities.logs = false` and the route answers "not supported".
#[derive(Debug, Clone)]
pub enum LogSource {
    /// A guest VM: proxy the in-guest `log-agent` (guest-hal layer
    /// service) over the per-VM `guest_to_host` /30 — e.g.
    /// `http://10.0.101.2:9300`. Its `GET /logs` returns JSON records
    /// `{timestamp, priority, message, source}` (mirror-by-convention;
    /// the guest tree is a different repo).
    GuestAgent { url: String },
    /// Host-local plain files (the supernova/host component): bounded
    /// tails of every file matching the globs (only `dir/prefix*suffix`
    /// patterns — no full glob engine). Lines carry the file's mtime.
    /// These produce STANDARD (line) log entries.
    HostFiles { globs: Vec<String> },
    /// Host-local dump DIRECTORY: the §7.21 CUSTOM-log catalog. Each file
    /// in `dir` is one retrievable dump artifact (a crash dump, captured
    /// trace, …) — listed with a stable id, `size`, and `log_type`/`status`
    /// from an optional `<name>.meta.json` sidecar (else defaults). Content
    /// = the file bytes; delete = unlink the file (+ sidecar). Unlike
    /// `HostFiles` (which tails text lines), this exposes whole files as
    /// discrete downloadable entries — the message-passing pattern.
    HostDumps { dir: String },
}

/// Per-component configuration for ComponentBackend behavior.
pub struct ComponentConfig {
    /// Whether this component supports rollback (false for HSM).
    pub supports_rollback: bool,
    /// Whether this component is single-banked (true for HSM — always bank A).
    pub single_bank: bool,
    /// SOVD entity_type for component identity.
    pub entity_type: String,
    /// §7.21 log sources, queried + merged by `get_logs`. Empty = the
    /// component serves no logs (`capabilities.logs = false` → route answers
    /// "not supported"). Additive: a component may have several (e.g. host
    /// text files + a dump directory), each contributing entries to one
    /// merged, timestamp-sorted list.
    pub log_sources: Vec<LogSource>,
}

impl Default for ComponentConfig {
    fn default() -> Self {
        Self {
            supports_rollback: true,
            single_bank: false,
            entity_type: "vm".to_string(),
            log_sources: Vec::new(),
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
    /// Session-scoped pull source (untrusted CAS base URL + trust anchor +
    /// campaign session id) for installs whose manifest references payloads by
    /// content-addressed URI. Set by the pull route BEFORE `start_flash` via
    /// [`set_install_source`](Self::set_install_source); cleared when the
    /// session ends (`clear_flash_session` / successful `finalize_flash`).
    /// Never set on the push path.
    install_source: Mutex<Option<machine_mgr::InstallSource>>,
    /// The bank the ECU is actually running on. Only changes on ecu_reset().
    /// NV active_bank may differ after install (it's the "next boot" bank).
    running_bank: Mutex<Bank>,
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
    /// Crypto handle (e.g. the host's shared link-B `LinkBClient`, or a SimHsm).
    /// The HSM-keys provision path builds the CEK `HsmKeyUnwrap` via `from_crypto`
    /// so device-decryption unwrap routes through `HsmCryptoProvider`. Required
    /// once the HSM is provisioned — the provision path errors without it.
    /// Threaded from `FactoryDeps::hsm_crypto` via
    /// [`with_hsm_crypto`](Self::with_hsm_crypto).
    hsm_crypto: Option<Arc<dyn hsm::HsmCryptoProvider>>,
    /// Sink that steps the host wall clock forward to the safe-time floor after
    /// an install ratchets it (see [`crate::sovd::time_floor`]). Defaults to the
    /// log-only [`NoopWallClockFloor`]; the real host injects a clock-setting
    /// impl via [`with_wall_clock_floor`](Self::with_wall_clock_floor).
    wall_clock_floor: Arc<dyn crate::sovd::time_floor::WallClockFloor>,
    /// Synthetic health source — consulted by `read_data` for
    /// `guest_state` / `heartbeat_seq` when `vm_service_addr` is None.
    /// Set via `with_health_probe` (typically by the host machine manager for the
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
    /// externally now (the host spawns the link-B backend), so this is the only
    /// reload path — there is no in-process daemon restart. `None` (the default)
    /// skips the reload. Threaded from `FactoryDeps::post_provision_reload` via
    /// [`with_post_provision_reload`](Self::with_post_provision_reload).
    post_provision_reload: Option<Arc<dyn Fn() + Send + Sync>>,
    /// The administrative-disable enactment seam — stops/erases this
    /// component's runtime when the operator disables it. Its PRESENCE is what
    /// makes the component disableable (structural, no name list): `None` ⇒
    /// the admin-state op answers "component does not support administrative
    /// disable". Injected by component-factory via
    /// [`with_deactivator`](Self::with_deactivator): VMs get the generic
    /// vm-service-stop deactivator, RT gets the deployment-injected erase,
    /// hsm/app/host-os never get one. The persisted flag itself lives in the
    /// shared NV admin-state record (`NvAdminState`), reached through
    /// [`Self::nv`].
    deactivator: Option<Arc<dyn machine_mgr::Deactivator>>,
}

impl<D: BlockDevice + Send + 'static> ComponentBackend<D> {
    pub fn new(
        bank_set: BankSet,
        nv: Arc<Mutex<NvStore<D>>>,
        manifest_provider: Arc<dyn ManifestProvider>,
        config: ComponentConfig,
    ) -> Self {
        Self::with_options(bank_set, nv, manifest_provider, config, None, None, None)
    }

    pub fn with_vm_service(
        bank_set: BankSet,
        nv: Arc<Mutex<NvStore<D>>>,
        manifest_provider: Arc<dyn ManifestProvider>,
        config: ComponentConfig,
        vm_service_addr: Option<String>,
    ) -> Self {
        Self::with_options(
            bank_set,
            nv,
            manifest_provider,
            config,
            vm_service_addr,
            None,
            None,
        )
    }

    pub fn with_options(
        bank_set: BankSet,
        nv: Arc<Mutex<NvStore<D>>>,
        manifest_provider: Arc<dyn ManifestProvider>,
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
                // Native SOVD server: privileged writes are authorized by the
                // JWT bearer token at the sovd-api layer — the UDS
                // session/security (seed/key) surface is retired.
                sessions: false,
                security: false,
                sub_entities: false,
                subscriptions: false,
                // §7.21: only components with a configured log source
                // serve logs; the rest keep the "not supported" answer.
                logs: !config.log_sources.is_empty(),
                operations: false,
            },
            bank_set,
            bank_spec,
            config,
            nv,
            manifest_provider,
            packages: Mutex::new(HashMap::new()),
            uploaded_parts: Mutex::new(HashMap::new()),
            manifests: Mutex::new(HashMap::new()),
            payloads: Mutex::new(HashMap::new()),
            flash_session: Mutex::new(None),
            flash_transfer: Mutex::new(None),
            install_source: Mutex::new(None),
            running_bank: Mutex::new(running_bank),
            next_id: Mutex::new(1),
            vm_service_addr,
            images_dir,
            upload_phase: Mutex::new(None),
            hsm_provider,
            // Defaults to the `dyn HsmProvider` path; component-factory injects a
            // crypto-only handle via `with_hsm_crypto` when link-B is configured.
            hsm_crypto: None,
            wall_clock_floor: Arc::new(crate::sovd::time_floor::NoopWallClockFloor),
            health_probe: None,
            did_cache: std::sync::RwLock::new(std::collections::HashMap::new()),
            manifest_describe: Mutex::new(HashMap::new()),
            verified_manifest_cache: Mutex::new(None),
            bank_provider,
            bank_provider_override: false,
            bank_activator: None,
            node_coordinator: None,
            post_provision_reload: None,
            deactivator: None,
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

    /// Inject the crypto handle (e.g. the host's shared link-B `LinkBClient`, or
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

    /// Inject the wall-clock-floor sink. The real host passes a clock-setting
    /// impl so an install that ratchets the safe-time floor also steps
    /// `CLOCK_REALTIME` forward to it; the default is the log-only no-op.
    pub fn with_wall_clock_floor(
        mut self,
        sink: Arc<dyn crate::sovd::time_floor::WallClockFloor>,
    ) -> Self {
        self.wall_clock_floor = sink;
        self
    }

    /// Ratchet the HSM's monotonic safe-time floor to `iat` (a manifest's signed
    /// `signing_time`, seconds) and discipline the host wall clock forward to the
    /// resulting floor. `iat` MUST come from a manifest whose signature already
    /// verified to a trusted root — it is a signed lower bound on real time
    /// (`docs/safe-time-floor.md`).
    ///
    /// The floor is monotonic (`raise_monotonic` = max), so this is safe to call on
    /// ANY trust-root-verified manifest — including one the caller then REJECTS for
    /// anti-rollback / device-identity reasons: a stale manifest's `iat` can only be
    /// a no-op against the floor, never a rewind, and a rejected manifest still
    /// carried a truthful signed lower bound on time. Advancing here (not gated on
    /// acceptance / trial-boot / commit) is what lets an offline device move its
    /// floor forward whenever it sees trusted signed time. Best-effort: a floor
    /// hiccup never fails an otherwise-valid operation.
    fn ratchet_time_floor(&self, iat: u64) {
        let Some(hsm) = self.hsm_provider.as_ref() else {
            return;
        };
        let mut hsm_guard = match hsm.lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::warn!("HSM provider lock poisoned — skipped time-floor ratchet");
                return;
            }
        };
        match crate::sovd::time_floor::TimeFloor::advance(&mut *hsm_guard, iat) {
            Ok(floor) => {
                tracing::info!(
                    iat,
                    floor,
                    "safe-time floor ratcheted from manifest signing time"
                );
                // Discipline the host wall clock forward to the resulting
                // (post-ratchet, max) floor, so every reader of CLOCK_REALTIME sees
                // max(now, floor) without a separate cache. Forward-only + best-effort.
                drop(hsm_guard);
                self.wall_clock_floor.discipline_to(floor);
            }
            Err(e) => {
                tracing::warn!(iat, error = %e, "could not ratchet safe-time floor from manifest iat")
            }
        }
    }

    /// Salvage the trusted signed time from a manifest we're about to REJECT.
    /// A `RollbackRejected` manifest still had its signature verified to a trusted
    /// root, so its `signing_time` is a truthful lower bound on real time — ratchet
    /// the floor from it before the rejection propagates. Other rejections (bad
    /// signature, parse error) carry no trusted time and are ignored.
    fn ratchet_time_floor_on_reject(&self, err: &crate::manifest_provider::ManifestError) {
        if let crate::manifest_provider::ManifestError::RollbackRejected {
            signing_time_secs: Some(iat),
            ..
        } = err
        {
            tracing::info!(iat, "ratcheting safe-time floor from a rejected (too-old) but trust-root-signed manifest");
            self.ratchet_time_floor(*iat);
        }
    }

    // --- §7.21 log-entry resolution (stateless, by the self-describing id) ---

    /// Re-derive a log entry from its id by re-listing the relevant source and
    /// matching. Stateless: the id says which source + how to match, so a
    /// restart (or a fresh process) resolves the same id identically while the
    /// underlying line/dump still exists.
    async fn find_log_entry(&self, log_id: &str) -> Option<LogEntry> {
        // Reject a malformed id up front (no source query for garbage). The
        // parse result isn't otherwise needed — matching is by the full id
        // string, which is content-addressed / path-encoded per kind.
        parse_log_id(log_id)?;
        // Broad re-list (no filter) of the sources, then match by id. Cheap
        // relative to the network/file cost already paid, and avoids a cache.
        let filter = LogFilter::default();
        let mut all: Vec<LogEntry> = Vec::new();
        for source in &self.config.log_sources {
            match source {
                LogSource::GuestAgent { url } => {
                    if let Some(e) = query_log_agent(url, &filter).await {
                        all.extend(e);
                    }
                }
                LogSource::HostFiles { globs } => all.extend(host_file_logs(globs, &filter)),
                LogSource::HostDumps { dir } => all.extend(host_dump_logs(dir, &filter)),
            }
        }
        all.into_iter().find(|e| e.id == log_id)
    }

    /// Resolve a `dump:host:<file>` id to an on-disk path under this component's
    /// configured `HostDumps` dir. Returns `EntityNotFound` if the component has
    /// no dump dir or the file isn't in it. The id carries only a bare filename
    /// (parse_log_id rejects separators/`..`), so this cannot escape the dir.
    fn resolve_dump_path(&self, log_id: &str, file: &str) -> BackendResult<std::path::PathBuf> {
        for source in &self.config.log_sources {
            if let LogSource::HostDumps { dir } = source {
                let path = std::path::Path::new(dir).join(file);
                if path.is_file() {
                    return Ok(path);
                }
            }
        }
        Err(BackendError::EntityNotFound(log_id.to_string()))
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
    /// (e.g. the host machine manager's RT raw-partition provider). Sets the override flag
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

    /// Equip this component with its administrative-disable enactment
    /// (`Deactivator`) — which is what MAKES it disableable (see the field
    /// docs). Also flips `capabilities.operations` on, since the component
    /// now advertises the `x-sumo-admin-state` op in `list_operations`.
    /// Threaded from `FactoryDeps::deactivators` / built by component-factory.
    pub fn with_deactivator(mut self, deactivator: Arc<dyn machine_mgr::Deactivator>) -> Self {
        self.deactivator = Some(deactivator);
        self.capabilities.operations = true;
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

    /// Reconcile the manifested-but-un-pushed components
    /// `[next_component .. total_components)` so the target bank is
    /// content-complete, each part DIGEST-VERIFIED against the manifest's
    /// declared plaintext image digest. Per part, in order:
    ///
    /// 1. **Copy-forward** from the active bank when its on-disk content hashes
    ///    to exactly what the manifest declared ("the vehicle already has
    ///    this" — the push path's manifest-only case, and the pull path's
    ///    cheap local half of copy-vs-fetch).
    /// 2. **Fetch by content-address** when copy-forward can't satisfy the
    ///    part AND the pull route provided a session [`machine_mgr::InstallSource`]
    ///    AND the (T2-signed) manifest URI carries a content-address: the blob
    ///    streams from the untrusted CAS through the two-checksum pipeline
    ///    (outer = signed content-address, inner = manifest `image_digest`)
    ///    straight into the target bank.
    /// 3. Otherwise FAIL the install rather than sealing a bank whose bytes
    ///    don't match the manifest's promise.
    ///
    /// Returns the copied files as an [`hsm::ivd::IvdFile`] inventory so the caller
    /// can fold them into the flash transfer's `streamed_files` (parity with the
    /// pushed path). A no-op returning empty when there are no un-pushed components.
    async fn reconcile_unpushed(
        &self,
        manifest_bytes: &[u8],
        next_component: usize,
        total_components: usize,
        target: Bank,
    ) -> BackendResult<Vec<hsm::ivd::IvdFile>> {
        if next_component >= total_components {
            return Ok(Vec::new());
        }
        let images_dir = self.images_dir.as_ref().ok_or_else(|| {
            BackendError::Internal(
                "manifest-only push needs an images_dir to reconcile the target bank".into(),
            )
        })?;

        // Resolve the active bank from NV; `target` is its sibling (never self-copy).
        let active = {
            let nv = self
                .nv
                .lock()
                .map_err(|_| BackendError::Internal("nv lock".into()))?;
            let state = nv
                .read_boot_state()
                .ok_or_else(|| BackendError::Internal("no boot state".into()))?;
            state.banks[self.bank_set.as_index()].active_bank
        };
        if active == target {
            return Err(BackendError::Internal(
                "copy-forward: target bank == active bank — refusing to self-copy".into(),
            ));
        }

        let set_name = self.bank_spec.dir_name.as_str();
        let active_dir = images_dir
            .join(set_name)
            .join(crate::bank_provider::bank_dir_name(active));
        let target_dir = images_dir
            .join(set_name)
            .join(crate::bank_provider::bank_dir_name(target));

        // Decode the stored manifest — `validated.image_sha256` is None for a
        // header-only manifest, so the per-component expected digest comes from
        // the SUIT manifest itself.
        let envelope = sumo_codec::decode::decode_envelope(manifest_bytes)
            .map_err(|e| BackendError::Internal(format!("reconcile decode manifest: {e:?}")))?;
        let manifest = sumo_onboard::manifest::Manifest { envelope };

        // One puller per reconcile pass, built lazily on the first part that
        // needs a fetch — push-path finalizes never pay for it.
        let mut cas_puller: Option<puller::Puller> = None;

        let mut done = Vec::with_capacity(total_components - next_component);
        for i in next_component..total_components {
            let expected = manifest
                .image_digest(i)
                .map(|d| d.0.bytes.clone())
                .ok_or_else(|| {
                    BackendError::Internal(format!(
                        "reconcile: manifest has no image_digest for component {i}"
                    ))
                })?;
            // Name from the component-id part, not the (content-address) uri.
            let name = crate::bank_spec::payload_target_name_for_id(manifest.component_id(i));

            match crate::bank_seed::copy_forward_file(&active_dir, &target_dir, &name, &expected) {
                Ok((sha256, size)) => {
                    tracing::info!(
                        component = i,
                        file = %name,
                        size,
                        "reconcile: active bank content matches manifest digest — copied to target",
                    );
                    done.push(hsm::ivd::IvdFile {
                        relative_path: name,
                        sha256: sha256.to_vec(),
                        size,
                    });
                }
                Err(copy_err) => {
                    // Copy-forward can't satisfy this part — fall back to
                    // fetching it by content-address IF the pull route provided
                    // a session source and the (signed) manifest URI carries an
                    // address. Otherwise the copy-forward refusal stands: never
                    // seal a bank whose bytes don't match the manifest promise.
                    let source = self.install_source.lock().unwrap().clone();
                    let uri = manifest.uri(i).map(str::to_owned);
                    let fetchable = source
                        .zip(uri)
                        .filter(|(_, u)| puller::content_address_sha256(u).is_some());
                    let Some((src, uri)) = fetchable else {
                        return Err(BackendError::Internal(format!(
                            "reconcile refused for component {i}: {copy_err}; \
                             no fetch source / content-addressed uri to fall back to"
                        )));
                    };
                    if cas_puller.is_none() {
                        cas_puller = Some(
                            puller::Puller::new(&src.cas_base_url, &src.trust_anchor).map_err(
                                |e| BackendError::Internal(format!("reconcile: build puller: {e}")),
                            )?,
                        );
                    }
                    let p = cas_puller.as_ref().unwrap();
                    // `sha256:<hex>` names content but isn't fetchable as-is —
                    // map it onto the repo's blob path. The mapped path still
                    // carries the content-address for the outer verify.
                    let path = puller::cas_fetch_path(&uri);
                    let outer_size = p.blob_size(&path).await.map_err(|e| {
                        BackendError::Internal(format!(
                            "reconcile: blob size for component {i}: {e}"
                        ))
                    })?;
                    // CAS temp lives beside the bank dirs (NOT inside the
                    // target bank) so start_flash's bank wipe never destroys a
                    // resumable partial.
                    let cas_tmp = images_dir.join(set_name).join("cas");
                    std::fs::create_dir_all(&cas_tmp).map_err(|e| {
                        BackendError::Internal(format!("reconcile: create cas tmp dir: {e}"))
                    })?;
                    let writer = self
                        .bank_provider
                        .open_payload_writer(target, &name)
                        .map_err(|e| {
                            BackendError::Internal(format!(
                                "reconcile: open bank writer for {name}: {e}"
                            ))
                        })?;
                    let key_unwrap = self.manifest_provider.key_unwrap_for_decryption();
                    let fetched = crate::streaming::fetch_and_install_component(
                        p,
                        &path,
                        outer_size,
                        manifest_bytes,
                        i,
                        key_unwrap,
                        &expected,
                        writer,
                        &cas_tmp,
                    )
                    .await;
                    let (size, sha256) = match fetched {
                        Ok(x) => x,
                        Err(e) => {
                            // `open_payload_writer` pre-created the bank file;
                            // a failed fetch must not leave even a partial
                            // artifact in the target bank (mirror of
                            // copy_forward_file's remove-on-mismatch). The
                            // resumable ciphertext partial in `cas/` is kept.
                            let _ = std::fs::remove_file(target_dir.join(&name));
                            return Err(e);
                        }
                    };
                    tracing::info!(
                        component = i,
                        file = %name,
                        size,
                        uri = %uri,
                        "reconcile: fetched by content-address into the target bank \
                         (copy-forward said: {copy_err})",
                    );
                    done.push(hsm::ivd::IvdFile {
                        relative_path: name,
                        sha256: sha256.to_vec(),
                        size: size as u64,
                    });
                }
            }
        }
        Ok(done)
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
        *self.install_source.lock().unwrap() = None;
        self.packages.lock().unwrap().clear();
        self.manifests.lock().unwrap().clear();
        self.payloads.lock().unwrap().clear();
        self.manifest_describe.lock().unwrap().clear();
    }

    /// Provide the session-scoped pull source for the NEXT install session —
    /// see [`machine_mgr::InstallSource`]. Called by the pull route before
    /// `start_flash`; overwrites any previous value. Enables the fetch
    /// fallback in `finalize_flash`'s reconciliation and stamps the campaign
    /// session id on the node update-transaction gate.
    pub fn set_install_source(&self, source: machine_mgr::InstallSource) {
        *self.install_source.lock().unwrap() = Some(source);
    }

    /// Terminal session teardown shared by every abort path: drop the staging
    /// session AND resolve this component's node-transaction membership (the
    /// gate staged it at `start_flash`). Pre-finalize only — callers reject
    /// post-finalize aborts first.
    pub fn abort_session(&self) -> BackendResult<()> {
        self.clear_flash_session();
        self.resolve_node_transaction()
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
        // FIRST: an administratively disabled component is not a flash target
        // — enable it before flashing (fleet side, the BOM convergence enables
        // first). Same Busy → HTTP 409 wire path as the trial refusal below.
        // This refusal is also what keeps the admission rule airtight: a
        // disabled component can never acquire `committed == false`.
        if self.admin_disabled() {
            return Err(BackendError::Busy(
                "component is administratively disabled — enable it before flashing".into(),
            ));
        }

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
        // `vm-sovd` injects the coordinator. The session id is zero for the push
        // path; the pull route stamps the L1 campaign id via `install_source`, so
        // one campaign's components Join a single node transaction and anything
        // unrelated gets Mixing-refused. In-trial is wired with the verdict
        // lifecycle.
        if let Some(coord) = &self.node_coordinator {
            let durable = self.node_reboot_owed()?;
            let session_id = self
                .install_source
                .lock()
                .unwrap()
                .as_ref()
                .and_then(|s| s.session_id)
                .unwrap_or([0u8; 32]);
            coord
                .gate_new_session(session_id, &self.entity_info.id, &durable, &[])
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
    // Per-component administrative state (disable/enable)
    // =================================================================

    /// True when this component is administratively disableable — i.e. the
    /// factory equipped it with a [`machine_mgr::Deactivator`]. Structural
    /// capability, never a name list.
    pub fn is_disableable(&self) -> bool {
        self.deactivator.is_some()
    }

    /// The component's *effective* administrative state: `true` only for a
    /// disableable component whose persisted NV flag is set. A stale NV bit
    /// on a component with no deactivator (the deployment shape changed)
    /// reads as enabled — the equipped deactivator is the authority on
    /// disableability. Fail-open to enabled on a poisoned lock, matching the
    /// NV record's own absent/corrupt contract ([`nv_store::types::NvAdminState`]).
    pub fn admin_disabled(&self) -> bool {
        self.is_disableable()
            && self
                .nv
                .lock()
                .map(|nv| nv.read_admin_state().is_disabled(self.bank_set))
                .unwrap_or(false)
    }

    /// Set the component's persisted administrative state and enact it.
    ///
    /// - Non-disableable (no deactivator) ⇒ `NotSupported` (the op's 400).
    /// - Idempotent: already in the requested state ⇒ no-op success.
    /// - **Disable is admitted only when idle**: own bank set committed, no
    ///   open flash session here, and no node transaction owing this
    ///   component its activation reboot — else `Busy` (the op's 409). The
    ///   payoff: a disabled component can never hold `committed == false`,
    ///   so the node-phase derivation, boot-trial counting, and verdict
    ///   fan-out need no disabled-awareness at all (assert, don't filter).
    /// - Ordering on disable: persist the flag FIRST, then enact via the
    ///   deactivator — a crash between the two converges at the next boot
    ///   (the start gate skips a disabled component). An enact failure keeps
    ///   the component disabled and is reported in
    ///   [`machine_mgr::AdminStateOutcome::enact_error`].
    /// - On enable: clear the flag, then best-effort start for VMs (the
    ///   NV-active bank). Activator-backed components (RT) stay empty —
    ///   content returns via a normal campaign re-flash.
    pub async fn set_admin_state(
        &self,
        disable: bool,
    ) -> BackendResult<machine_mgr::AdminStateOutcome> {
        let Some(deactivator) = self.deactivator.clone() else {
            return Err(BackendError::NotSupported(
                "component does not support administrative disable".into(),
            ));
        };

        // Idempotent no-op: nothing to admit or enact.
        if self.admin_disabled() == disable {
            return Ok(machine_mgr::AdminStateOutcome {
                disabled: disable,
                reboot_required: false,
                enact_error: None,
            });
        }

        if disable {
            // Admission (idle-only). (a) Own bank set committed — the mirror
            // of `ensure_flash_can_start`'s trial refusal.
            if !self.config.single_bank {
                let nv = self
                    .nv
                    .lock()
                    .map_err(|_| BackendError::Internal("nv lock".into()))?;
                let state = nv
                    .read_boot_state()
                    .ok_or_else(|| BackendError::Internal("no boot state".into()))?;
                if !state.banks[self.bank_set.as_index()].committed {
                    return Err(BackendError::Busy(format!(
                        "bank set {:?} is in trial mode (uncommitted) — commit or roll back \
                         the pending upgrade before disabling",
                        self.bank_set
                    )));
                }
            }
            // (b) No open flash session on this component (in-memory staging
            // is node-transaction membership too).
            if self.flash_in_progress() {
                return Err(BackendError::Busy(
                    "a flash session is in progress on this component — resolve it before \
                     disabling"
                        .into(),
                ));
            }
            // (c) No durable node transaction owing this component its
            // activation reboot (the reboot-owed record survives power cuts).
            {
                let nv = self
                    .nv
                    .lock()
                    .map_err(|_| BackendError::Internal("nv lock".into()))?;
                if nv
                    .read_update_session()
                    .unwrap_or_default()
                    .owes(self.bank_set)
                {
                    return Err(BackendError::Busy(
                        "this component owes the node a pending activation reboot — resolve \
                         the update transaction before disabling"
                            .into(),
                    ));
                }
            }

            // Persist FIRST, then enact: a crash after the write converges at
            // the next boot (start gate + autostart skip the disabled set).
            self.write_admin_flag(true)?;

            // The deactivator is sync and may legitimately block for the
            // guest's graceful-shutdown window — run it off the async worker.
            let enact = tokio::task::spawn_blocking(move || deactivator.deactivate()).await;
            let (reboot_required, enact_error) = match enact {
                Ok(Ok(outcome)) => (outcome.reboot_required, None),
                Ok(Err(e)) => (false, Some(e.to_string())),
                Err(e) => (false, Some(format!("deactivator task join error: {e}"))),
            };
            match &enact_error {
                None => tracing::info!(
                    component = %self.entity_info.id,
                    reboot_required,
                    "component administratively disabled"
                ),
                Some(e) => tracing::warn!(
                    component = %self.entity_info.id,
                    error = %e,
                    "component administratively disabled, but enacting the stop failed \
                     (flag persisted — the start gate keeps it down)"
                ),
            }
            Ok(machine_mgr::AdminStateOutcome {
                disabled: true,
                reboot_required,
                enact_error,
            })
        } else {
            // Enable: clear the flag first (the start gate reads NV), then
            // best-effort start for VMs. RT/activator components stay empty
            // until a campaign re-flash delivers content — nothing to start.
            self.write_admin_flag(false)?;

            let mut enact_error = None;
            if let Some(addr) = self.vm_service_addr.clone() {
                let active_bank = if self.config.single_bank {
                    Some(Bank::A)
                } else {
                    self.nv
                        .lock()
                        .ok()
                        .and_then(|nv| nv.read_boot_state())
                        .map(|s| s.banks[self.bank_set.as_index()].active_bank)
                };
                let id = &self.entity_info.id;
                if let Err(e) = Self::notify_vm_service(&addr, id, "start", active_bank).await {
                    tracing::warn!(
                        component = %id,
                        error = %e,
                        "component administratively enabled, but the vm-service start failed \
                         (flag cleared — a later reset/start will bring it up)"
                    );
                    enact_error = Some(format!("vm-service start: {e}"));
                } else {
                    tracing::info!(component = %id, "component administratively enabled — start requested");
                }
            } else {
                tracing::info!(
                    component = %self.entity_info.id,
                    "component administratively enabled (no vm-service — content returns via re-flash)"
                );
            }
            Ok(machine_mgr::AdminStateOutcome {
                disabled: false,
                reboot_required: false,
                enact_error,
            })
        }
    }

    /// Read-modify-write this component's bit in the shared NV admin-state
    /// record. Atomic under the NV mutex (single guard scope), so concurrent
    /// ops on sibling components can't lose each other's bits.
    fn write_admin_flag(&self, disabled: bool) -> BackendResult<()> {
        let mut nv = self.nv_write()?;
        let mut state = nv.read_admin_state();
        state.set_disabled(self.bank_set, disabled);
        nv.write_admin_state(&mut state)
            .map_err(|e| BackendError::Internal(format!("nv write admin-state: {e:?}")))
    }

    // =================================================================
    // Separate manifest + payload upload methods (new flash path)
    // =================================================================

    /// Upload a manifest (small CBOR envelope without integrated payloads).
    /// Validates signature + anti-rollback. Returns manifest_id.
    pub fn receive_manifest(&self, data: &[u8]) -> BackendResult<String> {
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

            // Name from the component-id part, not the (possibly content-address)
            // uri — see `payload_target_name_for_id`.
            let target_name =
                crate::bank_spec::payload_target_name_for_id(suit_manifest.component_id(comp_idx));

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
                .inspect_err(|e| self.ratchet_time_floor_on_reject(e))
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
        // Name the bank file from the component-id part, NOT the payload uri: the
        // uri is the content-address fetch reference (sha256:<outer>) and would
        // otherwise land the file as `sha256:…` (un-bootable).
        let target_name =
            crate::bank_spec::payload_target_name_for_id(manifest.component_id(comp_idx));

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

    /// SOVD §7.21 `GET /components/{id}/logs` — served only when the
    /// deployment config gives this component a [`LogSource`]
    /// (`capabilities.logs` gates the route in sovd-api). A guest VM is
    /// proxied to its in-guest log-agent; the host component tails its
    /// own files. Errors degrade to an EMPTY list with one `warn` — a
    /// down VM must not turn a log read into a 500.
    async fn get_logs(&self, filter: &LogFilter) -> BackendResult<Vec<LogEntry>> {
        // Query every configured source and merge. Each entry carries a stable,
        // self-describing id (see `log_id_*`) so get_log / get_log_content /
        // delete_log can route back to the right source without server state.
        let mut entries: Vec<LogEntry> = Vec::new();
        for source in &self.config.log_sources {
            match source {
                LogSource::GuestAgent { url } => match query_log_agent(url, filter).await {
                    Some(e) => entries.extend(e),
                    None => tracing::warn!(
                        component = %self.entity_info.id, url = %url,
                        "log-agent unreachable — skipping this source"
                    ),
                },
                LogSource::HostFiles { globs } => entries.extend(host_file_logs(globs, filter)),
                LogSource::HostDumps { dir } => entries.extend(host_dump_logs(dir, filter)),
            }
        }
        // Merge order: newest first (mirrors the gateway + single-source shape).
        entries.sort_by_key(|e| std::cmp::Reverse(e.timestamp));
        Ok(entries)
    }

    /// SOVD §7.21 paged log access + our reboot-safe cursor extension
    /// (`tasks/log-retrieval-design.md`). Overrides the trait default (one
    /// terminal page) ONLY for the pure HOST-FILE component: a component whose
    /// every source is [`LogSource::HostFiles`] pages forward over a
    /// `(boot_epoch, per-source byte offset)` cursor via [`host_file_logs_paged`].
    ///
    /// Multi-source handling (design doc step 5): a component that mixes in a
    /// GuestAgent or HostDumps source falls back to the DEFAULT single terminal
    /// page (the whole `get_logs` result, `next_cursor = None`). Those sources
    /// have no monotonic ordering key yet (guest paging is the journald-cursor
    /// follow-up; dumps are a whole-file catalog, not a line stream), and
    /// conflating a paged host offset with an unpaged dump list in one cursor
    /// would be incorrect. Picking the simplest correct option: paginate iff the
    /// source set is purely HostFiles; otherwise defer to the terminal-page
    /// default. A client's "loop until next_cursor is None" still terminates in
    /// one step against the fallback, exactly as with any non-paging backend.
    async fn get_logs_paged(&self, filter: &LogFilter) -> BackendResult<LogPage> {
        let only_host_files = !self.config.log_sources.is_empty()
            && self
                .config
                .log_sources
                .iter()
                .all(|s| matches!(s, LogSource::HostFiles { .. }));

        if only_host_files {
            // Merge every HostFiles source's globs into one source set — the
            // per-source cursor keys on the file stem, so multiple globs page
            // as one coherent resource.
            let mut globs: Vec<String> = Vec::new();
            for s in &self.config.log_sources {
                if let LogSource::HostFiles { globs: g } = s {
                    globs.extend(g.iter().cloned());
                }
            }
            Ok(host_file_logs_paged(&globs, filter, current_boot_epoch()))
        } else {
            // Default behaviour (mirrors the trait default): one terminal page.
            Ok(LogPage {
                items: self.get_logs(filter).await?,
                next_cursor: None,
                oldest_cursor: None,
            })
        }
    }

    /// SOVD §7.21 `GET /components/{id}/logs/{id}` — one entry's metadata.
    /// The id is self-describing (`<kind>:<source>:<key>`); we re-derive the
    /// entry from its backing source rather than hold server state.
    async fn get_log(&self, log_id: &str) -> BackendResult<LogEntry> {
        self.find_log_entry(log_id)
            .await
            .ok_or_else(|| BackendError::EntityNotFound(log_id.to_string()))
    }

    /// SOVD §7.21 `GET …/logs/{id}` with `Accept: application/octet-stream` —
    /// the entry's raw bytes. For a dump this is the file; for a standard line
    /// it is the line text (utf-8).
    async fn get_log_content(&self, log_id: &str) -> BackendResult<Vec<u8>> {
        match parse_log_id(log_id) {
            Some(ParsedLogId::HostDump { file }) => {
                let path = self.resolve_dump_path(log_id, &file)?;
                std::fs::read(&path).map_err(|e| {
                    BackendError::Internal(format!("read dump {}: {e}", path.display()))
                })
            }
            Some(ParsedLogId::Line) => {
                // A standard line's "content" is the line itself.
                let entry = self
                    .find_log_entry(log_id)
                    .await
                    .ok_or_else(|| BackendError::EntityNotFound(log_id.to_string()))?;
                Ok(entry.message.into_bytes())
            }
            Some(ParsedLogId::GuestDump) => Err(BackendError::NotSupported(
                "guest dump content (guest /dumps proxy not yet wired)".to_string(),
            )),
            None => Err(BackendError::EntityNotFound(log_id.to_string())),
        }
    }

    /// SOVD §7.21 `DELETE …/logs/{id}` — ack/remove. Only meaningful for a
    /// retrievable dump (unlink the file + sidecar); a standard journal/text
    /// line is not individually deletable.
    async fn delete_log(&self, log_id: &str) -> BackendResult<()> {
        match parse_log_id(log_id) {
            Some(ParsedLogId::HostDump { file }) => {
                let path = self.resolve_dump_path(log_id, &file)?;
                std::fs::remove_file(&path).map_err(|e| {
                    BackendError::Internal(format!("delete dump {}: {e}", path.display()))
                })?;
                // Best-effort sidecar removal. It is `<name>.meta.json` (the full
                // filename + suffix, per host_dump_logs) — NOT with_extension,
                // which would drop the dump's own extension (crash.bin →
                // crash.meta.json) and orphan the real sidecar.
                let _ = std::fs::remove_file(path.with_file_name(format!("{file}.meta.json")));
                Ok(())
            }
            Some(ParsedLogId::Line) => Err(BackendError::NotSupported(
                "a standard log line cannot be individually deleted".to_string(),
            )),
            Some(ParsedLogId::GuestDump) => Err(BackendError::NotSupported(
                "guest dump delete (guest /dumps proxy not yet wired)".to_string(),
            )),
            None => Err(BackendError::EntityNotFound(log_id.to_string())),
        }
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

    // --- Operations ---

    /// Cheap discoverability: a disableable component advertises the vendor
    /// `x-sumo-admin-state` op (id + name + href only); everything else keeps
    /// the empty list. The execution itself is served by the vendor router
    /// (`crate::sovd::admin_state`), not by `start_operation`.
    async fn list_operations(&self) -> BackendResult<Vec<OperationInfo>> {
        let mut ops = Vec::new();
        let id = &self.entity_info.id;
        if self.is_disableable() {
            let op = crate::sovd::admin_state::ADMIN_STATE_OP_ID;
            ops.push(OperationInfo {
                id: op.to_string(),
                name: "Administrative state (disable/enable)".to_string(),
                description: None,
                parameters: vec![],
                requires_security: false,
                security_level: 0,
                href: format!("/vehicle/v1/components/{id}/operations/{op}/executions"),
            });
        }
        // attest-time is device-global (ratchets the shared safe-time floor); it
        // needs an HSM (the floor slot) and is advertised ONCE, on the host/device
        // component (BankSet::Os), so it doesn't appear per-firmware-component.
        if self.hsm_provider.is_some() && self.bank_set == BankSet::Os {
            let op = ATTEST_TIME_OP_ID;
            ops.push(OperationInfo {
                id: op.to_string(),
                name: "Attest trusted time (advance the safe-time floor)".to_string(),
                description: Some(
                    "POST a SoftwareAuthority-signed SUIT manifest (hex); the device \
                     ratchets its safe-time floor from the manifest's signed signing_time."
                        .to_string(),
                ),
                parameters: vec![],
                requires_security: false,
                security_level: 0,
                href: format!("/vehicle/v1/components/{id}/operations/{op}/executions"),
            });
        }
        Ok(ops)
    }

    async fn start_operation(
        &self,
        operation_id: &str,
        params: &[u8],
    ) -> BackendResult<OperationExecution> {
        match operation_id {
            // Attest trusted time: verify a SoftwareAuthority-signed SUIT manifest
            // (params = the raw SUIT envelope bytes) and ratchet the safe-time floor
            // from its signed signing_time. Verify-only — validate_header_only does
            // signature+digest against the sw-authority anchor, no payload/bank work;
            // min_security_ver = 0 so an OLD manifest is accepted here (its signed
            // time is still a trusted lower bound; the floor is monotonic, so an
            // older-than-floor value is a harmless no-op).
            ATTEST_TIME_OP_ID => {
                let validated = self
                    .manifest_provider
                    .validate_header_only(params, 0)
                    .map_err(|e| {
                        BackendError::InvalidRequest(format!("attest-time manifest: {e}"))
                    })?;
                match validated.signing_time_secs {
                    Some(iat) => {
                        self.ratchet_time_floor(iat);
                        let floor = self
                            .hsm_provider
                            .as_ref()
                            .and_then(|h| h.lock().ok())
                            .and_then(|g| crate::sovd::time_floor::TimeFloor::read(&*g).ok())
                            .unwrap_or(iat);
                        Ok(OperationExecution::completed(
                            operation_id,
                            operation_id,
                            serde_json::json!({ "signing_time_secs": iat, "floor_secs": floor }),
                        ))
                    }
                    // Signature verified, but the manifest carried no signing_time —
                    // nothing to attest. A caller error (send one with an iat).
                    None => Err(BackendError::InvalidRequest(
                        "attest-time manifest has no signed signing_time to attest".to_string(),
                    )),
                }
            }
            _ => Err(BackendError::OperationNotFound(operation_id.to_string())),
        }
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
            .inspect_err(|e| self.ratchet_time_floor_on_reject(e))
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
        let (
            meta,
            image_data,
            image_size,
            pre_sha256,
            pre_size,
            manifest_type,
            raw_envelope,
            signing_time_secs,
        ) = {
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
                p.validated.signing_time_secs,
            )
        };

        // Safe-time floor: ratchet from the verified manifest's signing time (iat).
        // See ratchet_time_floor — monotonic, best-effort, done as soon as the
        // manifest is verified (not gated on trial-boot / commit).
        if let Some(iat) = signing_time_secs {
            self.ratchet_time_floor(iat);
        }

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
        // Manifest-only / partial push reconciliation. The orchestrator pushed
        // the L2 manifest but no payload for some components — "the vehicle
        // already has these" (push path) or "fetch them yourself" (pull path).
        // Those components were never streamed, so the seal/sign that the
        // final payload upload normally fires never ran — finalize would
        // otherwise activate an empty, unsigned target bank (the guest can't
        // boot it → trial-boot exhaustion → auto-rollback). Detect the
        // un-pushed tail `[next_component .. total_components)` and reconcile
        // it per part: copy-forward from the active bank (digest-verified),
        // else fetch by the signed content-address when the pull route
        // provided a session source; then seal the now-complete bank. Only
        // meaningful with an on-disk bank (`images_dir`); in-memory test
        // backends have no bank to reconcile and keep their prior behaviour.
        let manifest_only = if self.images_dir.is_some() {
            let session = self.flash_session.lock().unwrap();
            match session.as_ref() {
                Some(FlashSessionState::AwaitingPayload {
                    manifest_bytes,
                    next_component,
                    total_components,
                    ..
                }) if *next_component < *total_components => {
                    Some((manifest_bytes.clone(), *next_component, *total_components))
                }
                _ => None,
            }
        } else {
            None
        };
        if let Some((manifest_bytes, next_component, total_components)) = manifest_only {
            let target = self.determine_target_bank()?;
            let reconciled = self
                .reconcile_unpushed(&manifest_bytes, next_component, total_components, target)
                .await?;
            // Fold the reconciled files into the transfer inventory (parity with
            // the streamed path), then seal the now-complete bank. `seal`'s own
            // presence-based seed no-ops the just-written files and IVD-signs the
            // full bank so external secure boot / commit accept it.
            {
                let mut ft = self.flash_transfer.lock().unwrap();
                if let Some(ref mut t) = *ft {
                    t.streamed_files.extend(reconciled);
                }
            }
            self.ivd_sign_staged_bank(target)?;
            // Content-complete: advance exactly like the final payload upload would.
            *self.flash_session.lock().unwrap() = Some(FlashSessionState::Complete);
            {
                let mut ft = self.flash_transfer.lock().unwrap();
                if let Some(ref mut t) = *ft {
                    t.state = FlashState::AwaitingActivation;
                }
            }
            tracing::info!(
                bank_set = ?self.bank_set,
                target = ?target,
                reconciled_components = total_components - next_component,
                "manifest-only push reconciled: un-pushed components copied forward or fetched; target sealed",
            );
        }

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
                            // now (the host spawns the link-B backend); when a
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
        // The install is applied — the session-scoped pull source has served
        // its purpose (a later commit/rollback never fetches).
        *self.install_source.lock().unwrap() = None;
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
        // Administratively disabled ⇒ skip the vm-service probe entirely (the
        // VM is down BY DESIGN — probing would only burn the health timeout)
        // and report the spec `status` as an honest `notReady`; the vendor
        // `admin_state` field below tells readers WHY.
        let disableable = self.is_disableable();
        let admin_disabled = self.admin_disabled();
        let health = if admin_disabled {
            None
        } else {
            match &self.vm_service_addr {
                Some(socket) => query_vm_health(socket, &self.entity_info.id).await,
                // No vm-service backing: an injected HealthProbe (e.g. RT/M7)
                // is the health source — cheap by trait contract (cached).
                None => self.health_probe.as_ref().and_then(|p| p.probe()),
            }
        };
        let status = if admin_disabled {
            EntityStatus::NotReady
        } else if self.vm_service_addr.is_none() && self.health_probe.is_none() {
            // No health source at all (app-style components): presence = ready.
            EntityStatus::Ready
        } else if health
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
        // Tri-state admin read-back: disableable components carry
        // `admin_state: "enabled" | "disabled"`; non-disableable ones omit
        // the field entirely — so UIs can tell "cannot be disabled" apart
        // from "enabled" and never offer a dead toggle.
        if disableable {
            runtime.insert(
                "admin_state".into(),
                serde_json::json!(if admin_disabled {
                    "disabled"
                } else {
                    "enabled"
                }),
            );
        }
        // Probe-contributed metadata rides the SAME uniform node as every
        // other per-component fact — never a bespoke per-component route.
        // Standard fields stay authoritative on key collision (or_insert);
        // a disabled component's read stays minimal.
        if !admin_disabled {
            if let Some(probe) = &self.health_probe {
                for (k, v) in probe.runtime_extensions() {
                    runtime.entry(k).or_insert(v);
                }
            }
        } else if let Some(probe) = &self.health_probe {
            // A deactivation that ARMS a node reboot (rt: the erase — the M7
            // keeps executing from SRAM until the node restarts) must stay
            // OBSERVABLE after the op response is gone. Derived, not stored:
            // disabled + the probe still reporting a running application ⇒
            // the reboot hasn't happened yet. Clears itself on the real
            // reboot (the loader finds an empty slot ⇒ probe goes quiet) —
            // immune to supernova respawns, no NV clearing to get wrong.
            if probe.probe().is_some() {
                runtime.insert("reboot_pending".into(), serde_json::json!(true));
            }
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

        // A reset must never resurrect an administratively disabled component
        // — skip the pre-reset health probe AND the vm-service (re)start
        // notify below. (vm-service's own admin gate would refuse the start
        // anyway; skipping keeps this end fail-closed too and avoids the
        // phantom probe timeout against a deliberately-stopped guest.)
        let admin_disabled = self.admin_disabled();

        // Was the guest running before this reset? Used ONLY to pick the
        // vm-service "restart" vs "start" intent (a never-started guest
        // shouldn't render as "Shutting Down"). The activation verdict is the
        // orchestrator's job now: it reads `/status` and confirms the guest's
        // heartbeat `boot_id` changed (a fresh lifetime) AND status==ready.
        // The device no longer keeps an in-memory boot_id baseline.
        let was_running = if self.config.single_bank || admin_disabled {
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
            if admin_disabled {
                tracing::info!(
                    component = %self.entity_info.id,
                    "administratively disabled — skipping the vm-service relaunch after reset"
                );
            } else {
                let target_bank = *self.running_bank.lock().unwrap();
                let id = &self.entity_info.id;
                match Self::notify_vm_service(socket_path, id, action, Some(target_bank)).await {
                    Ok(()) => tracing::info!("vm-service {action} requested for {id}"),
                    Err(e) => tracing::warn!("failed to notify vm-service for {id}: {e}"),
                }
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
        // Drop the session AND the coordinator staging membership (the gate
        // staged this component at start_flash; an abort is a terminal
        // resolution too). reboot-owed clear is a no-op here — abort is
        // rejected post-finalize above, so nothing was ever marked.
        self.abort_session()?;
        Ok(())
    }

    // No `modes/session` / `modes/security` here: this is a native SOVD
    // server, not a UDS ECU front. Privileged `/updates` writes are
    // authorized by the JWT bearer token at the sovd-api layer (ISO 17978-3
    // §5.4.4); in-vehicle UDS seed/key unlock is performed transparently
    // server-side by the UDS-device handler (SOVDd). Both mode routes fall
    // through to the `DiagnosticBackend` defaults (`NotSupported` → 501).
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
// `bank_set_dir_name` / `bank_file_names` retired earlier — the on-disk
// dir name lives on `BankSetSpec` in `crate::bank_spec` now and is read
// off `self.bank_spec.dir_name`. Bank filenames are the SUIT component-id
// part taken verbatim (`bank_spec::payload_target_name_for_id`), no remap.

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

    /// Extra per-component metadata for the `/status` `x-sumo-runtime` block —
    /// the ONE uniform per-component metadata node. Probe-specific facts
    /// (e.g. the M7 platform-loader counters) ride here; never a bespoke
    /// per-component route. Standard fields win on key collision, and the
    /// same cheapness contract as [`Self::probe`] applies (cache internally).
    fn runtime_extensions(&self) -> serde_json::Map<String, serde_json::Value> {
        serde_json::Map::new()
    }
}

/// Query vm-service health endpoint via TCP loopback.
/// Returns guest_state and hb_seq from the JSON response.
/// Query vm-service's `/vms/<name>/health` endpoint over TCP loopback.
///
/// **Async** intentionally: `component-mgr` runs on the same tokio runtime as
/// vm-service (the host embeds both). A blocking `std::net::TcpStream`
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

// ---------------------------------------------------------------------------
// §7.21 log sources (see ComponentConfig::log_sources)
// ---------------------------------------------------------------------------

/// One record from the guest log-agent's `GET /logs`. Field names are the
/// wire contract, mirrored by convention with `guest-vm-sdk`'s
/// `log-agent` crate (different repo — never a git dep).
#[derive(serde::Deserialize)]
struct AgentLogRecord {
    timestamp: String,
    priority: String,
    message: String,
    source: String,
}

fn priority_name(p: LogPriority) -> &'static str {
    match p {
        LogPriority::Emergency => "emergency",
        LogPriority::Alert => "alert",
        LogPriority::Critical => "critical",
        LogPriority::Error => "error",
        LogPriority::Warning => "warning",
        LogPriority::Notice => "notice",
        LogPriority::Info => "info",
        LogPriority::Debug => "debug",
    }
}

fn priority_from_name(s: &str) -> LogPriority {
    match s {
        "emergency" => LogPriority::Emergency,
        "alert" => LogPriority::Alert,
        "critical" => LogPriority::Critical,
        "error" => LogPriority::Error,
        "warning" => LogPriority::Warning,
        "notice" => LogPriority::Notice,
        "debug" => LogPriority::Debug,
        _ => LogPriority::Info,
    }
}

/// Percent-encode one query value (RFC 3986 unreserved pass-through).
fn qenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `GET {url}/logs?...` against the in-guest log-agent — hand-rolled
/// HTTP/1.1 over tokio (same shape as [`query_vm_health`]; no HTTP-client
/// crate in this tree). `None` = unreachable/bad response (the caller
/// logs and serves empty). Body capped at 4 MiB.
async fn query_log_agent(url: &str, filter: &LogFilter) -> Option<Vec<LogEntry>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let deadline = std::time::Duration::from_secs(5);
    let hostport = url.strip_prefix("http://").unwrap_or(url);
    let (hostport, base_path) = match hostport.split_once('/') {
        Some((hp, rest)) => (hp, format!("/{rest}")),
        None => (hostport, String::new()),
    };

    let mut qs: Vec<String> = Vec::new();
    if let Some(n) = filter.tail.or(filter.limit) {
        qs.push(format!("tail={n}"));
    }
    if let Some(s) = &filter.source {
        qs.push(format!("source={}", qenc(s)));
    }
    if let Some(p) = &filter.pattern {
        qs.push(format!("pattern={}", qenc(p)));
    }
    if let Some(p) = filter.priority {
        qs.push(format!("priority={}", priority_name(p)));
    }
    if let Some(t) = filter.since {
        qs.push(format!("since={}", qenc(&t.to_rfc3339())));
    }
    if let Some(t) = filter.until {
        qs.push(format!("until={}", qenc(&t.to_rfc3339())));
    }
    let target = if qs.is_empty() {
        format!("{base_path}/logs")
    } else {
        format!("{base_path}/logs?{}", qs.join("&"))
    };

    let mut stream = tokio::time::timeout(deadline, TcpStream::connect(hostport))
        .await
        .ok()?
        .ok()?;
    let request = format!("GET {target} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n");
    tokio::time::timeout(deadline, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;
    let mut buf = Vec::with_capacity(64 * 1024);
    tokio::time::timeout(
        deadline,
        (&mut stream).take(4 * 1024 * 1024).read_to_end(&mut buf),
    )
    .await
    .ok()?
    .ok()?;
    let response = std::str::from_utf8(&buf).ok()?;
    let (head, body) = response.split_once("\r\n\r\n")?;
    if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
        return None;
    }
    let records: Vec<AgentLogRecord> = serde_json::from_str(body).ok()?;

    let entries = records
        .into_iter()
        .map(|r| {
            let timestamp = chrono::DateTime::parse_from_rfc3339(&r.timestamp)
                .map(|t| t.with_timezone(&Utc))
                .unwrap_or(chrono::DateTime::<Utc>::UNIX_EPOCH);
            LogEntry {
                // Content-addressed stable id (same scheme as host lines) so a
                // guest line re-resolves on get_log without server state.
                id: line_log_id(&r.source, timestamp, &r.message),
                timestamp,
                priority: priority_from_name(&r.priority),
                message: r.message,
                source: Some(r.source),
                pid: None,
                fields: None,
                log_type: None,
                size: None,
                status: None,
                href: None,
                metadata: None,
            }
        })
        .collect();
    Some(entries)
}

// ---------------------------------------------------------------------------
// Reboot-safe log pagination — HOST-FILE tier (tasks/log-retrieval-design.md)
//
// The wire cursor is OPAQUE to clients (base64url of a compact JSON). It carries
// a per-boot epoch plus a per-source resume byte offset. WHY each piece exists:
//
//   * A byte offset into an append-only file is ALREADY reboot-safe: a byte
//     position is monotonic no matter what the host's 1970→floor→1970 wall clock
//     does. So offset alone pages PERSISTENT files (/var/log, log-rotate'd)
//     correctly across a reboot — the offset stays valid.
//   * boot_epoch has ONE job: INVALIDATE offsets for VOLATILE sources. A file
//     under /dev/shmem (QNX RAM) is wiped on reboot, so a saved offset into it is
//     meaningless post-reboot. When the cursor's boot_epoch differs from the
//     current one AND the source is volatile, we restart that source from 0.
//   * boot_epoch is NOT a per-line key (MM does not own most host log lines —
//     they're written by other producers into arbitrary glob'd files), so we do
//     NOT stamp lines with it. It is purely a cursor-invalidation tag.
// ---------------------------------------------------------------------------

/// Environment override for the boot-epoch persistence file, so tests never
/// touch `/var/lib`. When unset, [`DEFAULT_BOOT_EPOCH_FILE`] is used.
const BOOT_EPOCH_FILE_ENV: &str = "MACHINE_MGR_BOOT_EPOCH_FILE";
/// Default persistence path for the boot-epoch counter. Deliberately a TINY
/// plain file, NOT nv-store: nv-store is safety-relevant + format-specced;
/// boot_epoch is only a log-cursor invalidation tag. Worst case if it's lost or
/// reset = volatile cursors restart from oldest = SAFE (design doc Q1).
const DEFAULT_BOOT_EPOCH_FILE: &str = "/var/lib/machine-mgr/boot_epoch";

/// Process-wide cached boot epoch. Read + incremented + written back ONCE at the
/// first paged-log request (see [`current_boot_epoch`]); never bumped per-request.
static BOOT_EPOCH: OnceLock<u64> = OnceLock::new();

/// The default page size (entries) when the client sets neither `limit` nor
/// `tail`, and the hard cap — matches the non-paged `host_file_logs` path.
const PAGE_DEFAULT: usize = 200;
const PAGE_MAX: usize = 2000;

/// Return the process-wide boot epoch, reading + incrementing + persisting the
/// counter file on first call. Its only job is to invalidate cursors for
/// volatile log sources across a reboot; a read/write failure is NON-FATAL
/// (warn + fall back to an in-memory value) because a lost epoch merely restarts
/// volatile sources from oldest, which is safe.
fn current_boot_epoch() -> u64 {
    *BOOT_EPOCH.get_or_init(|| {
        let path = std::env::var(BOOT_EPOCH_FILE_ENV)
            .unwrap_or_else(|_| DEFAULT_BOOT_EPOCH_FILE.to_string());
        bump_boot_epoch_file(Path::new(&path))
    })
}

/// Read the u64 in `path` (0 if absent/unparseable), increment, write it back,
/// and return the incremented value. Failures to read/write are logged at
/// `warn` and treated as a 0 baseline (→ returns 1) so the daemon still boots.
fn bump_boot_epoch_file(path: &Path) -> u64 {
    let prev = match std::fs::read_to_string(path) {
        Ok(s) => s.trim().parse::<u64>().unwrap_or(0),
        // Absent file is the normal first-boot case (not a warn); other errors
        // (permissions, IO) are unusual — surface them but keep going.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e,
                "boot_epoch file unreadable — starting from 0 (volatile cursors will restart)");
            0
        }
    };
    let next = prev.saturating_add(1);
    // Best-effort persist: create the parent dir, then write. A failure only
    // means the NEXT boot re-uses this epoch → volatile cursors restart once
    // more; still safe, so we don't propagate the error.
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(path, next.to_string()) {
        tracing::warn!(path = %path.display(), error = %e,
            "boot_epoch file unwritable — epoch not persisted this boot");
    }
    next
}

/// Path-based volatility classification (design doc step 2): a file under
/// `/dev/shmem` (QNX RAM) is VOLATILE — wiped on reboot, so a saved offset into
/// it is meaningless across boots. Everything else (log-rotate'd `/var/log`
/// files) is PERSISTENT — a byte offset survives the reboot unchanged.
fn is_volatile(path: &Path) -> bool {
    path.starts_with("/dev/shmem")
}

/// Per-source position within the cursor: the file's rotation generation and the
/// byte offset to RESUME reading at (the offset AFTER the last complete line
/// returned). Compact single-letter keys keep the encoded cursor small.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct SourcePos {
    /// Rotation generation: 0 = the live base file `{path}`; 1 = `{path}.1`; etc.
    /// FIRST CUT: we page only the live base file, so `g` is always 0 today (see
    /// `host_file_logs_paged` TODO). It is carried so a later rotated-set pager
    /// can populate it without a cursor-format change.
    #[serde(rename = "g")]
    gen: u64,
    /// Byte offset to resume at.
    #[serde(rename = "o")]
    offset: u64,
}

/// The decoded log cursor. Wire form is base64url(no-pad) of this struct's JSON;
/// clients NEVER parse it (journald discipline — see design doc).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct LogCursor {
    /// The boot epoch this cursor was minted under. If it differs from the
    /// current epoch, offsets into volatile sources are void.
    #[serde(rename = "b")]
    boot_epoch: u64,
    /// Per-source resume position, keyed by the file-stem source name that
    /// `host_file_logs` already uses. `BTreeMap` for a deterministic key order
    /// (stable encoded cursor, easier round-trip assertions).
    #[serde(rename = "s")]
    sources: BTreeMap<String, SourcePos>,
}

impl LogCursor {
    /// Encode as an opaque base64url(no-pad) token. Reuses the crate's existing
    /// `b64url` helper (same encoding as the log-id scheme) — no new dep.
    fn encode(&self) -> String {
        // serde_json on a small fixed struct cannot realistically fail; if it
        // ever did, an empty string decodes back to "no cursor" (start oldest),
        // which is the safe fallback rather than a 500.
        serde_json::to_vec(self).map(|j| b64url(&j)).unwrap_or_default()
    }

    /// Decode an opaque token. Returns `None` for any malformed input so the
    /// caller treats a bad cursor as "no cursor" (start from oldest) — never a
    /// 500, per the design contract.
    fn decode(token: &str) -> Option<LogCursor> {
        let bytes = b64url_decode(token)?;
        serde_json::from_slice(&bytes).ok()
    }
}

/// Reboot-safe, paginable variant of [`host_file_logs`]. Reads FORWARD from each
/// source's cursor offset (not a last-64KB tail), returns the entries plus a
/// `next_cursor` advanced past what it consumed, and an `oldest_cursor` pointing
/// at offset 0 for every source under the current boot epoch.
///
/// FIRST CUT — base-file-only paging: we page the live base file `{path}` (gen
/// 0) only. Rotated files (`{path}.1`, `{path}.2`, …) are NOT yet walked — that
/// is the documented follow-up (see the `gen` field). We STILL detect rotation /
/// truncation via the offset-vs-length gap check below, so we never silently
/// skip or re-read: if the file shrank under a saved offset we restart it from 0.
fn host_file_logs_paged(globs: &[String], filter: &LogFilter, boot_epoch: u64) -> LogPage {
    let cursor = filter.after.as_deref().and_then(LogCursor::decode);
    // A cursor minted under a different boot epoch only invalidates VOLATILE
    // sources; persistent offsets stay valid (a byte position is reboot-stable).
    let cursor_epoch = cursor.as_ref().map(|c| c.boot_epoch);

    let page_size = filter
        .tail
        .or(filter.limit)
        .unwrap_or(PAGE_DEFAULT)
        .min(PAGE_MAX);

    let files = resolve_log_files(globs);

    let mut items: Vec<LogEntry> = Vec::new();
    // The next cursor's per-source offsets and the oldest (offset-0) positions.
    let mut next_sources: BTreeMap<String, SourcePos> = BTreeMap::new();
    let mut oldest_sources: BTreeMap<String, SourcePos> = BTreeMap::new();
    // Did we read anything new from ANY source? If not, next_cursor = None so a
    // client's paging loop terminates (they've reached the head).
    let mut produced_any = false;

    for path in files {
        let source = source_name(&path);
        // Every resolved source contributes an oldest (offset-0) position.
        oldest_sources.insert(source.clone(), SourcePos { gen: 0, offset: 0 });

        // Source filter: honour it exactly as host_file_logs does.
        if let Some(want) = &filter.source {
            if want != &source {
                continue;
            }
        }

        // mtime drives the entry timestamp AND the since/until pre-filter (same
        // coarse semantics as host_file_logs — these are file-level, not
        // per-line, because host lines are unstructured text with no timestamp).
        let mtime = file_mtime(&path);
        if let Some(since) = filter.since {
            if mtime < since {
                // Skipped by time — but still resume from where the cursor was so
                // a later mtime bump doesn't replay the whole file.
                if let Some(pos) = cursor.as_ref().and_then(|c| c.sources.get(&source)) {
                    next_sources.insert(source.clone(), *pos);
                }
                continue;
            }
        }
        if let Some(until) = filter.until {
            if mtime > until {
                if let Some(pos) = cursor.as_ref().and_then(|c| c.sources.get(&source)) {
                    next_sources.insert(source.clone(), *pos);
                }
                continue;
            }
        }

        let file_len = match std::fs::metadata(&path) {
            Ok(m) => m.len(),
            Err(_) => continue, // vanished/unreadable → skip (not an error)
        };

        // Determine the resume offset for this source.
        let saved = cursor.as_ref().and_then(|c| c.sources.get(&source));
        let volatile = is_volatile(&path);
        let start_offset = match saved {
            // No cursor, or this source absent from it → start at oldest.
            None => 0,
            Some(pos) => {
                if cursor_epoch != Some(boot_epoch) && volatile {
                    // Volatile source across a reboot → offset void, restart.
                    0
                } else if pos.offset > file_len {
                    // File shrank (truncated / rotated / replaced) → GAP. Restart
                    // from 0; oldest_cursor (offset 0) will be > the client's
                    // `after` so they can detect the dropped history.
                    0
                } else {
                    pos.offset
                }
            }
        };

        // Read forward from start_offset, collecting COMPLETE lines and tracking
        // the byte offset after the last complete line consumed. A torn trailing
        // partial line is NOT consumed — its bytes stay for the next call.
        let remaining = page_size.saturating_sub(items.len());
        let (lines, new_offset) = match read_lines_from(&path, start_offset, remaining) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if new_offset > start_offset {
            produced_any = true;
        }
        // Record where this source resumes next time. Even a source we didn't
        // advance keeps its position so the cursor stays complete.
        next_sources.insert(
            source.clone(),
            SourcePos {
                gen: 0,
                offset: new_offset,
            },
        );

        for line in lines {
            if let Some(pat) = &filter.pattern {
                if !line.contains(pat.as_str()) {
                    continue;
                }
            }
            items.push(LogEntry {
                // Same content-addressed id scheme as host_file_logs so a paged
                // line re-resolves via get_log identically.
                id: line_log_id(&source, mtime, &line),
                timestamp: mtime,
                priority: LogPriority::Info,
                message: line,
                source: Some(source.clone()),
                pid: None,
                fields: None,
                log_type: None,
                size: None,
                status: None,
                href: None,
                metadata: None,
            });
        }

        if items.len() >= page_size {
            // Page full. Stop scanning; sources we never reached are carried
            // below (post-loop) so the next call resumes rather than replays
            // them. We break AFTER recording this source's advanced offset above.
            break;
        }
    }

    // Carry any source present in the INCOMING cursor that this scan didn't
    // touch (e.g. sources past a page-fill break, or one currently filtered out
    // by since/until): keep its prior offset so the next call resumes it instead
    // of replaying from oldest. New (never-seen) sources are intentionally NOT
    // synthesised here — they enter next_sources only once actually scanned.
    if let Some(c) = &cursor {
        for (source, pos) in &c.sources {
            next_sources.entry(source.clone()).or_insert(*pos);
        }
    }

    // Priority filter is "this level and above" (§7.21): lower enum value = more
    // severe. Host lines are always Info; keep the check for parity + future
    // structured sources.
    if let Some(p) = filter.priority {
        items.retain(|e| e.priority <= p);
    }

    let oldest_cursor = Some(
        LogCursor {
            boot_epoch,
            sources: oldest_sources,
        }
        .encode(),
    );

    // next_cursor = None when nothing new was read from ANY source (head
    // reached) → the client's loop stops. Otherwise carry the advanced offsets.
    let next_cursor = if produced_any {
        Some(
            LogCursor {
                boot_epoch,
                sources: next_sources,
            }
            .encode(),
        )
    } else {
        None
    };

    LogPage {
        items,
        next_cursor,
        oldest_cursor,
    }
}

/// Resolve a set of `dir/prefix*suffix` (or literal) globs to a sorted, deduped
/// list of existing regular files. Extracted from `host_file_logs` so the paged
/// and non-paged readers resolve identically. Only ONE `*` in the filename
/// position is supported (no full glob engine) — a literal path matches itself.
fn resolve_log_files(globs: &[String]) -> Vec<std::path::PathBuf> {
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    for g in globs {
        let p = std::path::Path::new(g);
        match p.file_name().and_then(|f| f.to_str()) {
            Some(name) if name.contains('*') => {
                let (prefix, suffix) = name.split_once('*').unwrap_or((name, ""));
                let dir = p.parent().unwrap_or(std::path::Path::new("/"));
                if let Ok(rd) = std::fs::read_dir(dir) {
                    for e in rd.flatten() {
                        let f = e.file_name();
                        let f = f.to_string_lossy();
                        if f.starts_with(prefix) && f.ends_with(suffix) && e.path().is_file() {
                            files.push(e.path());
                        }
                    }
                }
            }
            _ => {
                if p.is_file() {
                    files.push(p.to_path_buf());
                }
            }
        }
    }
    files.sort();
    files.dedup();
    files
}

/// The source name for a log file — its file stem (matches `host_file_logs`).
fn source_name(path: &std::path::Path) -> String {
    path.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "host".into())
}

/// A file's mtime as a UTC timestamp (UNIX epoch if unavailable) — the timestamp
/// stamped on every line from that file, matching `host_file_logs`.
fn file_mtime(path: &std::path::Path) -> chrono::DateTime<Utc> {
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .map(chrono::DateTime::<Utc>::from)
        .unwrap_or(chrono::DateTime::<Utc>::UNIX_EPOCH)
}

/// Read forward from `start` in `path`, returning up to `max` COMPLETE lines and
/// the byte offset AFTER the last complete line consumed. A torn trailing partial
/// line (no terminating `\n`) is NOT consumed — its bytes are left for the next
/// call, so a line being appended concurrently is never split across pages.
/// Blank/whitespace-only lines are skipped (parity with `tail_file_lines`) but
/// their bytes still advance the offset so we don't re-scan them.
fn read_lines_from(
    path: &std::path::Path,
    start: u64,
    max: usize,
) -> std::io::Result<(Vec<String>, u64)> {
    use std::io::{BufRead, BufReader, Seek, SeekFrom};

    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::Start(start))?;
    let mut reader = BufReader::new(f);

    let mut lines: Vec<String> = Vec::new();
    let mut offset = start;
    // Read raw bytes so we can distinguish a complete line (ends in `\n`) from a
    // torn trailing partial (EOF with no newline) — `BufRead::lines` hides that.
    loop {
        if lines.len() >= max {
            break;
        }
        let mut raw: Vec<u8> = Vec::new();
        let n = reader.read_until(b'\n', &mut raw)?;
        if n == 0 {
            break; // EOF
        }
        if raw.last() != Some(&b'\n') {
            // Torn partial line at EOF — do NOT consume it or advance past it.
            break;
        }
        // Complete line: advance the offset past it regardless of whether we keep
        // it (blank lines still move the cursor so they aren't re-scanned).
        offset += n as u64;
        let text = String::from_utf8_lossy(&raw);
        let trimmed = text.trim_end_matches(['\n', '\r']);
        if !trimmed.trim().is_empty() {
            lines.push(trimmed.to_string());
        }
    }
    Ok((lines, offset))
}

/// Host-local file logs: bounded tails of every file matching the globs.
/// Only `dir/prefix*suffix` patterns (one `*`, filename position) — a
/// literal path matches itself. Lines carry the file's mtime; priority
/// is `Info` (host logs are unstructured text).
fn host_file_logs(globs: &[String], filter: &LogFilter) -> Vec<LogEntry> {
    const PER_FILE_CAP: u64 = 64 * 1024;
    const MAX_ENTRIES: usize = 2000;

    let files = resolve_log_files(globs);

    let mut entries: Vec<LogEntry> = Vec::new();
    for path in files {
        let source = source_name(&path);
        if let Some(want) = &filter.source {
            if want != &source {
                continue;
            }
        }
        let mtime = file_mtime(&path);
        if let Some(since) = filter.since {
            if mtime < since {
                continue;
            }
        }
        if let Some(until) = filter.until {
            if mtime > until {
                continue;
            }
        }
        let lines = match tail_file_lines(&path, PER_FILE_CAP) {
            Ok(l) => l,
            Err(_) => continue,
        };
        for line in lines.into_iter() {
            if let Some(pat) = &filter.pattern {
                if !line.contains(pat.as_str()) {
                    continue;
                }
            }
            entries.push(LogEntry {
                // Stable, content-addressed id so get_log/get_log_content can
                // re-find this line by re-listing + matching (no server state,
                // stable across re-list while the line exists).
                id: line_log_id(&source, mtime, &line),
                timestamp: mtime,
                priority: LogPriority::Info,
                message: line,
                source: Some(source.clone()),
                pid: None,
                fields: None,
                log_type: None,
                size: None,
                status: None,
                href: None,
                metadata: None,
            });
            if entries.len() >= MAX_ENTRIES {
                break;
            }
        }
    }
    // Priority filter is "this level and above" (§7.21): lower enum value =
    // higher severity (Emergency=0 … Debug=7), so keep entries at or above.
    if let Some(p) = filter.priority {
        entries.retain(|e| e.priority <= p);
    }
    let tail = filter.tail.or(filter.limit).unwrap_or(200).min(MAX_ENTRIES);
    if entries.len() > tail {
        entries.drain(..entries.len() - tail);
    }
    entries
}

/// Last `cap` bytes of `path`, split into non-empty lines (a torn first
/// line after the seek is dropped). Mirrors the guest agent's reader.
fn tail_file_lines(path: &std::path::Path, cap: u64) -> std::io::Result<Vec<String>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    let mut torn = false;
    if len > cap {
        f.seek(SeekFrom::Start(len - cap))?;
        torn = true;
    }
    let mut buf = Vec::with_capacity(cap.min(len) as usize);
    f.take(cap).read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf);
    let mut lines: Vec<String> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_string())
        .collect();
    if torn && !lines.is_empty() {
        lines.remove(0);
    }
    Ok(lines)
}

// ---------------------------------------------------------------------------
// §7.21 log id scheme — stable, self-describing, STATELESS.
//
// `get_log`/`get_log_content`/`delete_log` must route an id back to its source
// without a server-side id→artifact map (which would be lost on restart and
// race the message-passing delete). So the id encodes everything needed:
//
//   line:<source>:<b64url(sha256(source|ts|message)[..12])>   a standard line
//   dump:host:<b64url(filename)>                               a host dump file
//   dump:<vmN>:<agent-id>                                      a guest dump (future)
//
// base64url(no-pad) keeps ids URL-clean. `dump:host` encodes only the FILE NAME
// (not the dir) — the dir comes from the component's own HostDumps config at
// fetch time, so the id can't be used to escape that dir (path-traversal safe).
// ---------------------------------------------------------------------------

fn b64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()
}

/// Content-addressed id for a standard log line (stable while the line exists).
fn line_log_id(source: &str, ts: chrono::DateTime<Utc>, message: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(source.as_bytes());
    h.update(b"|");
    h.update(ts.to_rfc3339().as_bytes());
    h.update(b"|");
    h.update(message.as_bytes());
    let digest = h.finalize();
    format!("line:{source}:{}", b64url(&digest[..12]))
}

/// Id for a host dump file — encodes the bare filename (dir is config-supplied).
fn dump_log_id(file_name: &str) -> String {
    format!("dump:host:{}", b64url(file_name.as_bytes()))
}

/// A parsed §7.21 log id — tells the backend how to route get/content/delete.
/// Carries only what routing consumes today; the id string itself remains the
/// authoritative key (content-addressed for lines, path-encoded for dumps).
enum ParsedLogId {
    /// A standard journal/text line — re-found by re-listing sources and
    /// matching the full id (stable while the line exists), so no payload needed.
    Line,
    /// A host dump file: `file` is the decoded bare filename (no dir component;
    /// the dir comes from the component's `HostDumps` config).
    HostDump { file: String },
    /// A guest dump served by the guest log-agent. The routing target (vm +
    /// agent id) is re-parsed when the guest `/dumps` proxy is wired; today this
    /// only selects the "not yet supported" branch.
    GuestDump,
}

fn parse_log_id(id: &str) -> Option<ParsedLogId> {
    let (kind, rest) = id.split_once(':')?;
    match kind {
        "line" => {
            // Shape check only: `line:<source>:<hash>` must have both colons.
            rest.rsplit_once(':')?;
            Some(ParsedLogId::Line)
        }
        "dump" => {
            let (src, key) = rest.split_once(':')?;
            if src == "host" {
                let file = String::from_utf8(b64url_decode(key)?).ok()?;
                // Reject any decoded name that isn't a bare filename — no path
                // separators, no `..` — so the id can never escape the dump dir.
                if file.contains('/') || file.contains("..") || file.is_empty() {
                    return None;
                }
                Some(ParsedLogId::HostDump { file })
            } else {
                Some(ParsedLogId::GuestDump)
            }
        }
        _ => None,
    }
}

/// Optional sidecar next to a dump file: `<name>.meta.json` → { type, status }.
#[derive(Debug, serde::Deserialize)]
struct DumpMeta {
    #[serde(default, rename = "type")]
    log_type: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

/// Host dump DIRECTORY as a §7.21 CUSTOM-log catalog: each regular file in
/// `dir` (excluding `*.meta.json` sidecars) is one retrievable dump entry with
/// a stable id, `size`, and `log_type`/`status` from an optional sidecar. This
/// is the discovery surface for custom logs — content/delete address the file
/// by the id's encoded filename.
fn host_dump_logs(dir: &str, filter: &LogFilter) -> Vec<LogEntry> {
    const MAX_ENTRIES: usize = 2000;
    let mut entries: Vec<LogEntry> = Vec::new();
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return entries, // absent/unreadable dir → no dumps (not an error)
    };
    for e in rd.flatten() {
        let path = e.path();
        if !path.is_file() {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if name.ends_with(".meta.json") {
            continue; // sidecars aren't entries
        }
        let meta = std::fs::metadata(&path).ok();
        let size = meta.as_ref().map(|m| m.len());
        let mtime = meta
            .and_then(|m| m.modified().ok())
            .map(chrono::DateTime::<Utc>::from)
            .unwrap_or(chrono::DateTime::<Utc>::UNIX_EPOCH);

        // Optional sidecar for type/status.
        let sidecar = path.with_file_name(format!("{name}.meta.json"));
        let dm: Option<DumpMeta> = std::fs::read(&sidecar)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());
        let log_type = dm.as_ref().and_then(|m| m.log_type.clone());
        let status = match dm.as_ref().and_then(|m| m.status.as_deref()) {
            Some("retrieved") => Some(LogStatus::Retrieved),
            Some("processed") => Some(LogStatus::Processed),
            _ => Some(LogStatus::Pending),
        };

        // Filters: source (vs filename), type, status, since/until (mtime).
        if let Some(want) = &filter.source {
            if want != &name {
                continue;
            }
        }
        if let Some(t) = &filter.log_type {
            if log_type.as_deref() != Some(t.as_str()) {
                continue;
            }
        }
        if let Some(st) = filter.status {
            if status != Some(st) {
                continue;
            }
        }
        if let Some(since) = filter.since {
            if mtime < since {
                continue;
            }
        }
        if let Some(until) = filter.until {
            if mtime > until {
                continue;
            }
        }

        entries.push(LogEntry {
            id: dump_log_id(&name),
            timestamp: mtime,
            priority: LogPriority::Notice, // a dump is a notable artifact, not a line
            message: name.clone(),
            source: Some(name),
            pid: None,
            fields: None,
            log_type,
            size,
            status,
            href: None, // sovd-api synthesizes the bulk-data href from the id
            metadata: None,
        });
        if entries.len() >= MAX_ENTRIES {
            break;
        }
    }
    entries
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
    use hsm::HsmProvider;
    use hsm_sim_backend::SimHsm;
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

        let hsm = SimHsm::new(keystore.clone());
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
        let crypto: Arc<dyn hsm::HsmCryptoProvider> = Arc::new(SimHsm::new(keystore.clone()));
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
                    signing_time_secs: None,
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
            ComponentConfig {
                supports_rollback: false,
                single_bank: true,
                entity_type: "hsm".to_string(),
                log_sources: Vec::new(),
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

    /// §7.21: no log source => capability off + empty list (the route
    /// answers "not supported" via capabilities().logs).
    #[tokio::test]
    async fn logs_unsupported_without_source() {
        let b = backend();
        assert!(!b.capabilities().logs);
        let got = b.get_logs(&LogFilter::default()).await.unwrap();
        assert!(got.is_empty());
    }

    fn backend_with_logs(source: LogSource) -> ComponentBackend<MemBlockDevice> {
        let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
        let mut boot = NvBootState::default();
        nv.write_boot_state(&mut boot).unwrap();
        ComponentBackend::with_options(
            BankSet::Vm1,
            Arc::new(Mutex::new(nv)),
            Arc::new(NoopManifest),
            ComponentConfig {
                log_sources: vec![source],
                ..ComponentConfig::default()
            },
            None,
            None,
            None,
        )
    }

    /// §7.21 HostFiles source: bounded tails of matching files with
    /// source/pattern/tail filter semantics.
    #[tokio::test]
    async fn logs_host_files_globs_and_filters() {
        let dir = std::env::temp_dir().join(format!("cm-logs-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("supernova.log"), "one\ntwo\nthree\n").unwrap();
        std::fs::write(dir.join("other.log"), "alpha\nbeta\n").unwrap();
        std::fs::write(dir.join("skip.txt"), "not a log\n").unwrap();

        let b = backend_with_logs(LogSource::HostFiles {
            globs: vec![format!("{}/*.log", dir.display())],
        });
        assert!(b.capabilities().logs);

        let all = b.get_logs(&LogFilter::default()).await.unwrap();
        assert_eq!(all.len(), 5, "both .log files, txt excluded");
        assert!(all.iter().all(|e| e.priority == LogPriority::Info));

        let filtered = b
            .get_logs(&LogFilter {
                source: Some("supernova".into()),
                pattern: Some("t".into()),
                tail: Some(1),
                ..LogFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].message, "three");
        assert_eq!(filtered[0].source.as_deref(), Some("supernova"));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// §7.21 GuestAgent source: proxy a stub agent (canned JSON) and map
    /// records to LogEntry; an unreachable agent degrades to empty.
    #[tokio::test]
    async fn logs_guest_agent_proxy_and_degrade() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let body = r#"[{"timestamp":"2026-07-18T12:00:00Z","priority":"warning","message":"hb late","source":"vhealth"}]"#;
            for conn in listener.incoming().take(1) {
                let mut s = conn.unwrap();
                use std::io::{Read, Write};
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });

        let b = backend_with_logs(LogSource::GuestAgent {
            url: format!("http://{addr}"),
        });
        assert!(b.capabilities().logs);
        let got = b.get_logs(&LogFilter::default()).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].message, "hb late");
        assert_eq!(got[0].priority, LogPriority::Warning);
        assert_eq!(got[0].source.as_deref(), Some("vhealth"));
        assert_eq!(got[0].timestamp.to_rfc3339(), "2026-07-18T12:00:00+00:00");

        // Unreachable agent: empty list, not an error (the SOVD route
        // must stay 200 with [] when a VM is down).
        let b = backend_with_logs(LogSource::GuestAgent {
            url: "http://127.0.0.1:1".into(),
        });
        let got = b.get_logs(&LogFilter::default()).await.unwrap();
        assert!(got.is_empty());
    }

    /// Stable-id round-trip: an id from `get_logs` re-resolves via `get_log`
    /// and `get_log_content` (no server state) — the fix for the old ephemeral
    /// `{source}-{i}` ids that resolved nowhere.
    #[tokio::test]
    async fn logs_standard_line_id_round_trips() {
        let dir = std::env::temp_dir().join(format!("cm-logid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("svc.log"), "hello world\nsecond line\n").unwrap();

        let b = backend_with_logs(LogSource::HostFiles {
            globs: vec![format!("{}/*.log", dir.display())],
        });
        let listed = b.get_logs(&LogFilter::default()).await.unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().all(|e| e.id.starts_with("line:svc:")));

        // get_log by the listed id returns the same entry.
        let one = &listed[0];
        let fetched = b.get_log(&one.id).await.unwrap();
        assert_eq!(fetched.id, one.id);
        assert_eq!(fetched.message, one.message);

        // get_log_content returns the line's bytes.
        let content = b.get_log_content(&one.id).await.unwrap();
        assert_eq!(String::from_utf8(content).unwrap(), one.message);

        // a standard line is not deletable.
        assert!(matches!(
            b.delete_log(&one.id).await,
            Err(BackendError::NotSupported(_))
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Priority filter is "this level and above" (§7.21, numeric `<=`), not an
    /// exact match. Host-file lines are `Info` (6); the discriminating case is a
    /// `Debug` (7) threshold: "and-above" KEEPS the Info line (6 ≤ 7) where the
    /// old `==` semantics would have dropped it.
    #[tokio::test]
    async fn logs_priority_filter_is_and_above() {
        let dir = std::env::temp_dir().join(format!("cm-prio-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("svc.log"), "an info line\n").unwrap();
        let b = backend_with_logs(LogSource::HostFiles {
            globs: vec![format!("{}/*.log", dir.display())],
        });

        // threshold = Debug (least severe): everything at or above is kept — the
        // Info line survives. `==` would require priority == Debug and drop it.
        let kept = b
            .get_logs(&LogFilter {
                priority: Some(LogPriority::Debug),
                ..LogFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(kept.len(), 1, "Info is above Debug — and-above keeps it");

        // threshold = Warning (more severe than Info): the Info line is dropped.
        let dropped = b
            .get_logs(&LogFilter {
                priority: Some(LogPriority::Warning),
                ..LogFilter::default()
            })
            .await
            .unwrap();
        assert!(dropped.is_empty(), "Info is below Warning — filtered out");
        std::fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // Reboot-safe log pagination (tasks/log-retrieval-design.md, HOST tier)
    // -----------------------------------------------------------------------

    /// Cursor encode→decode preserves the boot epoch and every per-source
    /// (gen, offset). The token is opaque base64url; clients never parse it.
    #[test]
    fn log_cursor_round_trips() {
        let mut sources = BTreeMap::new();
        sources.insert("svc".to_string(), SourcePos { gen: 0, offset: 42 });
        sources.insert(
            "kern".to_string(),
            SourcePos {
                gen: 0,
                offset: 1_000_000,
            },
        );
        let c = LogCursor {
            boot_epoch: 7,
            sources,
        };
        let decoded = LogCursor::decode(&c.encode()).expect("round-trips");
        assert_eq!(decoded, c);
        assert_eq!(decoded.boot_epoch, 7);
        assert_eq!(decoded.sources["svc"].offset, 42);
        assert_eq!(decoded.sources["kern"].offset, 1_000_000);
    }

    /// A garbage `after` cursor is treated as "no cursor" (start from oldest),
    /// never a panic or 500.
    #[test]
    fn log_cursor_bad_token_is_none() {
        assert!(LogCursor::decode("").is_none());
        assert!(LogCursor::decode("!!!not-base64!!!").is_none());
        // Valid base64url of non-JSON bytes → still None (not a panic).
        assert!(LogCursor::decode(&b64url(b"\xff\xfe\x00garbage")).is_none());
    }

    /// Paging an append-only file in batches returns disjoint, in-order lines
    /// and terminates (next_cursor eventually None). Also: appending AFTER the
    /// head is reached and re-calling with the last cursor returns ONLY the new
    /// lines.
    #[test]
    fn log_paging_batches_disjoint_and_terminates() {
        let dir = std::env::temp_dir().join(format!("cm-page-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("svc.log");
        std::fs::write(&path, "l1\nl2\nl3\nl4\nl5\n").unwrap();
        let globs = vec![format!("{}/*.log", dir.display())];

        // Page size 2, boot epoch 1.
        let f = |after: Option<String>| LogFilter {
            limit: Some(2),
            after,
            ..LogFilter::default()
        };

        let p1 = host_file_logs_paged(&globs, &f(None), 1);
        let m1: Vec<_> = p1.items.iter().map(|e| e.message.clone()).collect();
        assert_eq!(m1, vec!["l1", "l2"]);
        assert!(p1.next_cursor.is_some());
        assert!(p1.oldest_cursor.is_some(), "oldest_cursor always reported");

        let p2 = host_file_logs_paged(&globs, &f(p1.next_cursor.clone()), 1);
        let m2: Vec<_> = p2.items.iter().map(|e| e.message.clone()).collect();
        assert_eq!(m2, vec!["l3", "l4"]);

        let p3 = host_file_logs_paged(&globs, &f(p2.next_cursor.clone()), 1);
        let m3: Vec<_> = p3.items.iter().map(|e| e.message.clone()).collect();
        assert_eq!(m3, vec!["l5"]);

        // Head reached: nothing new → next_cursor None (loop terminates).
        let p4 = host_file_logs_paged(&globs, &f(p3.next_cursor.clone()), 1);
        assert!(p4.items.is_empty());
        assert!(p4.next_cursor.is_none(), "no new bytes → head → None");

        // Append after EOF, re-call with the LAST non-None cursor (p3's): only
        // the new lines come back, none of l1..l5 replayed.
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(b"l6\nl7\n").unwrap();
        }
        let p5 = host_file_logs_paged(&globs, &f(p3.next_cursor.clone()), 1);
        let m5: Vec<_> = p5.items.iter().map(|e| e.message.clone()).collect();
        assert_eq!(m5, vec!["l6", "l7"], "only the newly-appended lines");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Volatile invalidation: a stale-epoch cursor against a /dev/shmem-style
    /// (volatile) path restarts from offset 0, while a persistent path with the
    /// SAME stale epoch keeps its offset. We exercise `is_volatile` directly (no
    /// real /dev/shmem needed) plus the offset-decision the pager uses.
    #[test]
    fn log_volatile_source_invalidated_across_reboot() {
        assert!(is_volatile(Path::new("/dev/shmem/foo.log")));
        assert!(!is_volatile(Path::new("/var/log/foo.log")));

        // Persistent file: a stale-epoch cursor's offset MUST be honoured — a
        // byte offset into an append-only file is reboot-safe.
        let dir = std::env::temp_dir().join(format!("cm-vol-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("persist.log");
        std::fs::write(&path, "a\nb\nc\nd\n").unwrap();
        let globs = vec![format!("{}/*.log", dir.display())];

        // Mint a cursor at boot epoch 1 that has already consumed "a\nb\n" (4 bytes).
        let mut sources = BTreeMap::new();
        sources.insert("persist".to_string(), SourcePos { gen: 0, offset: 4 });
        let stale = LogCursor {
            boot_epoch: 1,
            sources,
        }
        .encode();

        // Current epoch is 2 (a reboot happened). The path is PERSISTENT, so the
        // offset survives — we resume at "c", not restart at "a".
        let page = host_file_logs_paged(
            &globs,
            &LogFilter {
                after: Some(stale),
                ..LogFilter::default()
            },
            2,
        );
        let msgs: Vec<_> = page.items.iter().map(|e| e.message.clone()).collect();
        assert_eq!(
            msgs,
            vec!["c", "d"],
            "persistent offset honoured across reboot"
        );

        // The volatile decision itself: same stale epoch + volatile path ⇒ the
        // pager's start_offset logic resets to 0. We assert the classifier and
        // the epoch mismatch that together trigger the reset (the reset branch in
        // host_file_logs_paged keys on exactly `epoch_mismatch && is_volatile`).
        let epoch_mismatch = 1u64 != 2u64;
        assert!(epoch_mismatch && is_volatile(Path::new("/dev/shmem/x.log")));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Truncation/rotation gap: a cursor whose offset exceeds the current file
    /// length (file shrank) restarts that source from 0 rather than seeking past
    /// EOF and returning nothing.
    #[test]
    fn log_paging_truncation_restarts_from_oldest() {
        let dir = std::env::temp_dir().join(format!("cm-trunc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("svc.log");
        std::fs::write(&path, "fresh1\nfresh2\n").unwrap(); // 14 bytes
        let globs = vec![format!("{}/*.log", dir.display())];

        // Cursor claims offset 9999 (way past the 14-byte file) — the file was
        // clearly truncated/replaced. Same boot epoch so only the gap check fires.
        let mut sources = BTreeMap::new();
        sources.insert(
            "svc".to_string(),
            SourcePos {
                gen: 0,
                offset: 9999,
            },
        );
        let cur = LogCursor {
            boot_epoch: 5,
            sources,
        }
        .encode();

        let page = host_file_logs_paged(
            &globs,
            &LogFilter {
                after: Some(cur),
                ..LogFilter::default()
            },
            5,
        );
        let msgs: Vec<_> = page.items.iter().map(|e| e.message.clone()).collect();
        assert_eq!(msgs, vec!["fresh1", "fresh2"], "shrunk file → restart at 0");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// boot_epoch file: absent → first read yields 1; a second bump yields 2;
    /// the value persists across calls. Uses a temp path via the override so
    /// /var/lib is never touched.
    #[test]
    fn boot_epoch_file_increments_and_persists() {
        let dir = std::env::temp_dir().join(format!("cm-epoch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("boot_epoch");

        // Absent file → 0 baseline → returns 1, and persists "1".
        assert_eq!(bump_boot_epoch_file(&path), 1);
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), "1");
        // Second bump reads 1 → returns 2.
        assert_eq!(bump_boot_epoch_file(&path), 2);
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), "2");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Multi-source components (HostFiles + a non-paginable source) fall back to
    /// the DEFAULT single terminal page: next_cursor None so a client's loop
    /// still terminates in one step (design doc step 5 choice).
    #[tokio::test]
    async fn logs_paged_multisource_falls_back_to_terminal_page() {
        use sovd_core::DiagnosticBackend;
        let dir = std::env::temp_dir().join(format!("cm-multi-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("svc.log"), "one\ntwo\n").unwrap();

        // A component with BOTH a HostFiles and a HostDumps source → not pure
        // HostFiles → terminal page.
        let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
        let mut boot = NvBootState::default();
        nv.write_boot_state(&mut boot).unwrap();
        let b = ComponentBackend::with_options(
            BankSet::Vm1,
            Arc::new(Mutex::new(nv)),
            Arc::new(NoopManifest),
            ComponentConfig {
                log_sources: vec![
                    LogSource::HostFiles {
                        globs: vec![format!("{}/*.log", dir.display())],
                    },
                    LogSource::HostDumps {
                        dir: dir.to_string_lossy().into_owned(),
                    },
                ],
                ..ComponentConfig::default()
            },
            None,
            None,
            None,
        );

        let page = b.get_logs_paged(&LogFilter::default()).await.unwrap();
        assert!(
            page.next_cursor.is_none(),
            "mixed sources → terminal page, loop terminates"
        );
        // The host-file lines still appear in that one page.
        assert!(page.items.iter().any(|e| e.message == "one"));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Pure-HostFiles components DO paginate through `get_logs_paged`: the first
    /// page of a >page-size file sets a next_cursor.
    #[tokio::test]
    async fn logs_paged_pure_hostfiles_paginates() {
        use sovd_core::DiagnosticBackend;
        let dir = std::env::temp_dir().join(format!("cm-pure-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let body: String = (0..10).map(|i| format!("line{i}\n")).collect();
        std::fs::write(dir.join("svc.log"), body).unwrap();

        let b = backend_with_logs(LogSource::HostFiles {
            globs: vec![format!("{}/*.log", dir.display())],
        });
        let page = b
            .get_logs_paged(&LogFilter {
                limit: Some(3),
                ..LogFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(page.items.len(), 3);
        assert!(page.next_cursor.is_some(), "more to read → cursor set");
        assert!(page.oldest_cursor.is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// §7.21 CUSTOM logs: a dump directory is a catalog — list, fetch content
    /// by id, delete by id. Sidecar sets type/status.
    #[tokio::test]
    async fn logs_host_dumps_catalog_content_and_delete() {
        let dir = std::env::temp_dir().join(format!("cm-dumps-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("crash-001.bin"), b"\x00\x01\x02dump-bytes").unwrap();
        std::fs::write(
            dir.join("crash-001.bin.meta.json"),
            br#"{"type":"engine_dump","status":"pending"}"#,
        )
        .unwrap();

        let b = backend_with_logs(LogSource::HostDumps {
            dir: dir.to_string_lossy().into_owned(),
        });
        assert!(b.capabilities().logs);

        // Catalog: one dump, sidecar type/status, size, stable dump: id.
        let listed = b.get_logs(&LogFilter::default()).await.unwrap();
        assert_eq!(listed.len(), 1, "sidecar is not itself an entry");
        let d = &listed[0];
        assert!(d.id.starts_with("dump:host:"));
        assert_eq!(d.log_type.as_deref(), Some("engine_dump"));
        assert_eq!(d.status, Some(LogStatus::Pending));
        assert_eq!(d.size, Some(13)); // 3 raw bytes + "dump-bytes" (10)

        // Content by id = the file bytes.
        let content = b.get_log_content(&d.id).await.unwrap();
        assert_eq!(content, b"\x00\x01\x02dump-bytes");

        // Filter by type.
        let by_type = b
            .get_logs(&LogFilter {
                log_type: Some("engine_dump".into()),
                ..LogFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(by_type.len(), 1);

        // Delete by id removes the file AND its `<name>.meta.json` sidecar
        // (regression: with_extension would target crash-001.meta.json and
        // orphan the real crash-001.bin.meta.json).
        b.delete_log(&d.id).await.unwrap();
        assert!(!dir.join("crash-001.bin").exists());
        assert!(
            !dir.join("crash-001.bin.meta.json").exists(),
            "sidecar must be removed alongside the dump"
        );
        assert!(b.get_logs(&LogFilter::default()).await.unwrap().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A crafted dump id can't escape the dump dir (path-traversal defence).
    #[tokio::test]
    async fn logs_dump_id_cannot_escape_dir() {
        // parse_log_id must reject a decoded name containing separators / `..`.
        let evil = format!("dump:host:{}", b64url(b"../../etc/passwd"));
        assert!(
            parse_log_id(&evil).is_none(),
            "traversal name must not parse"
        );

        // And a valid-but-absent file id is EntityNotFound, not a read elsewhere.
        let b = backend_with_logs(LogSource::HostDumps {
            dir: "/nonexistent-dump-dir".into(),
        });
        let missing = dump_log_id("ghost.bin");
        assert!(matches!(
            b.get_log_content(&missing).await,
            Err(BackendError::EntityNotFound(_))
        ));
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

    fn backend() -> ComponentBackend<MemBlockDevice> {
        let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
        let mut boot = NvBootState::default();
        nv.write_boot_state(&mut boot).unwrap();
        ComponentBackend::with_options(
            BankSet::Vm1,
            Arc::new(Mutex::new(nv)),
            Arc::new(NoopManifest),
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

// ===========================================================================
// Copy-forward (manifest-only / partial push reconciliation)
// ===========================================================================
#[cfg(test)]
mod copy_forward_tests {
    use super::*;
    use crate::manifest_provider::ManifestError;
    use nv_store::block::MemBlockDevice;
    use nv_store::store::MIN_NV_DEVICE_SIZE;
    use sha2::{Digest, Sha256};
    use sumo_offboard::{keygen, ImageManifestBuilder};

    struct NoopManifest;
    impl ManifestProvider for NoopManifest {
        fn validate(&self, _d: &[u8], _m: u32) -> Result<ValidatedFirmware, ManifestError> {
            Err(ManifestError::ParseError(
                "unused in copy-forward tests".into(),
            ))
        }
    }
    /// A detached (no integrated payload) single-component SUIT manifest whose
    /// declared image digest is `digest` — mimics the offboard "manifest-only,
    /// you already have this" push. `component_id = ["vm1", part]` — the part
    /// segment is the on-disk bank filename, verbatim. The payload uri stays
    /// `#firmware` on purpose: naming must key off the id, never the uri.
    fn detached_manifest(part: &str, digest: &[u8], size: u64) -> Vec<u8> {
        let key = keygen::generate_signing_key(keygen::ES256).unwrap();
        ImageManifestBuilder::new()
            .signing_time(1_700_000_000)
            .component_id(vec!["vm1".into(), part.into()])
            .sequence_number(2)
            .payload_digest(digest, size)
            .payload_uri("#firmware".into())
            .build(&key)
            .unwrap()
    }

    fn vm1_backend(images_dir: PathBuf) -> ComponentBackend<MemBlockDevice> {
        let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
        let mut boot = NvBootState::default();
        boot.banks[BankSet::Vm1.as_index()].active_bank = Bank::A;
        nv.write_boot_state(&mut boot).unwrap();
        ComponentBackend::with_options(
            BankSet::Vm1,
            Arc::new(Mutex::new(nv)),
            Arc::new(NoopManifest),
            ComponentConfig::default(),
            None,
            Some(images_dir),
            None,
        )
    }

    /// Digest-match: the active bank's content hashes to what the manifest
    /// declares → copy it forward into the target bank + report the inventory.
    #[tokio::test]
    async fn reconcile_unpushed_copies_matching_component() {
        let tmp = tempfile::tempdir().unwrap();
        let images_dir = tmp.path().to_path_buf();
        let content = b"vm1 rootfs the vehicle already has";
        let active = images_dir.join("vm1/bank_a");
        std::fs::create_dir_all(&active).unwrap();
        std::fs::write(active.join("rootfs.img"), content).unwrap();
        let digest: [u8; 32] = Sha256::digest(content).into();

        let manifest = detached_manifest("rootfs.img", &digest, content.len() as u64);
        let backend = vm1_backend(images_dir.clone());

        let copied = backend
            .reconcile_unpushed(&manifest, 0, 1, Bank::B)
            .await
            .expect("digest matches → copy-forward");
        assert_eq!(copied.len(), 1);
        assert_eq!(copied[0].relative_path, "rootfs.img");
        assert_eq!(copied[0].sha256, digest.to_vec());
        assert_eq!(copied[0].size, content.len() as u64);
        assert_eq!(
            std::fs::read(images_dir.join("vm1/bank_b/rootfs.img")).unwrap(),
            content,
            "target bank_b gets the active bank's verified rootfs"
        );
    }

    /// Digest-mismatch with no fetch source: the active bank holds a different
    /// version than the manifest declares → the install must FAIL and stage
    /// nothing (never ship stale content).
    #[tokio::test]
    async fn reconcile_unpushed_fails_on_stale_active() {
        let tmp = tempfile::tempdir().unwrap();
        let images_dir = tmp.path().to_path_buf();
        let active = images_dir.join("vm1/bank_a");
        std::fs::create_dir_all(&active).unwrap();
        std::fs::write(active.join("rootfs.img"), b"STALE local rootfs").unwrap();

        let declared: [u8; 32] = Sha256::digest(b"the version offboard expects").into();
        let manifest = detached_manifest("rootfs.img", &declared, 42);
        let backend = vm1_backend(images_dir.clone());

        let err = backend
            .reconcile_unpushed(&manifest, 0, 1, Bank::B)
            .await
            .expect_err("digest mismatch → install must fail");
        assert!(matches!(err, BackendError::Internal(_)), "got {err:?}");
        assert!(
            !images_dir.join("vm1/bank_b/rootfs.img").exists(),
            "stale content must not be staged into the target bank"
        );
    }

    /// No un-pushed components (`next_component == total`) → no-op, empty result.
    #[tokio::test]
    async fn reconcile_unpushed_noop_when_all_pushed() {
        let tmp = tempfile::tempdir().unwrap();
        let images_dir = tmp.path().to_path_buf();
        let manifest = detached_manifest("rootfs.img", &[0u8; 32], 0);
        let backend = vm1_backend(images_dir);
        let copied = backend
            .reconcile_unpushed(&manifest, 1, 1, Bank::B)
            .await
            .expect("no un-pushed components");
        assert!(copied.is_empty());
    }

    /// Like `detached_manifest`, with an explicit payload uri — the pull shape
    /// puts the CONTENT-ADDRESS there.
    fn detached_manifest_with_uri(part: &str, digest: &[u8], size: u64, uri: &str) -> Vec<u8> {
        let key = keygen::generate_signing_key(keygen::ES256).unwrap();
        ImageManifestBuilder::new()
            .signing_time(1_700_000_000)
            .component_id(vec!["vm1".into(), part.into()])
            .sequence_number(2)
            .payload_digest(digest, size)
            .payload_uri(uri.into())
            .build(&key)
            .unwrap()
    }

    /// A session [`machine_mgr::InstallSource`] over `base` (anchor unused by
    /// blob fetches — blobs verify by content-address, not signature).
    fn test_source(base: String) -> machine_mgr::InstallSource {
        let key = keygen::generate_signing_key(keygen::ES256).unwrap();
        machine_mgr::InstallSource {
            cas_base_url: base,
            trust_anchor: key.public_key_bytes(),
            session_id: None,
        }
    }

    /// Minimal raw-HTTP/1.1 CAS for the reconcile fetch tests: serves `blobs`
    /// by exact path, honours HEAD (headers only) and `Range: bytes=N-` (206),
    /// logs every `"<METHOD> <path>"`, and optionally truncates the FIRST GET
    /// body after `early_close_once` bytes (then serves fully — the resume
    /// scenario).
    ///
    /// Teardown is deliberately graceful (drain the full request, then FIN via
    /// `shutdown`): an abrupt drop can turn into a TCP RST, and an RST discards
    /// data the client kernel has buffered but not yet read — which made the
    /// truncated-body bytes vanish under load (empty `.part`, flaky
    /// `reconcile_fetch_failure_is_retry_safe_and_resumes`). With a clean FIN
    /// plus a delivery gap after a truncated body (see below), the client
    /// reliably sees exactly the bytes written, then EOF.
    async fn serve_cas(
        blobs: std::collections::HashMap<String, Vec<u8>>,
        early_close_once: Option<usize>,
    ) -> (String, Arc<Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let log: Arc<Mutex<Vec<String>>> = Arc::default();
        let log_srv = log.clone();
        let cut = Arc::new(Mutex::new(early_close_once));
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(c) => c,
                    Err(_) => return,
                };
                let blobs = blobs.clone();
                let log = log_srv.clone();
                let cut = cut.clone();
                tokio::spawn(async move {
                    // Drain the whole request (headers end at the blank line;
                    // these requests carry no body). Unread request bytes at
                    // close would turn the close into an RST.
                    let mut buf = Vec::with_capacity(4096);
                    let mut chunk = [0u8; 4096];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let req = String::from_utf8_lossy(&buf).into_owned();
                    let mut first = req.lines().next().unwrap_or("").split_whitespace();
                    let method = first.next().unwrap_or("").to_string();
                    let path = first.next().unwrap_or("").to_string();
                    log.lock().unwrap().push(format!("{method} {path}"));
                    let Some(blob) = blobs.get(&path) else {
                        let _ = sock
                            .write_all(
                                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                        let _ = sock.shutdown().await;
                        return;
                    };
                    let start = req
                        .lines()
                        .find_map(|l| l.strip_prefix("Range: bytes="))
                        .and_then(|r| r.split('-').next())
                        .and_then(|s| s.trim().parse::<usize>().ok())
                        .filter(|s| *s <= blob.len());
                    let (line, mut body): (&str, &[u8]) = match start {
                        Some(s) => ("206 Partial Content", &blob[s..]),
                        None => ("200 OK", &blob[..]),
                    };
                    let full_len = body.len();
                    let mut truncated = false;
                    if method == "HEAD" {
                        body = &[];
                    } else if let Some(limit) = cut.lock().unwrap().take() {
                        if body.len() > limit {
                            body = &body[..limit];
                            truncated = true;
                        }
                    }
                    let head = format!(
                        "HTTP/1.1 {line}\r\nContent-Length: {full_len}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(body).await;
                    let _ = sock.flush().await;
                    if truncated {
                        // Separate the short body from the EOF in time. When
                        // the truncated bytes and the FIN reach the client as
                        // one read event, hyper races its buffered body chunk
                        // against the premature-EOF error and sometimes
                        // surfaces ONLY the error — the client then persists a
                        // 0-byte partial and the resume test loses its Range
                        // leg. With the gap, the client must consume the
                        // prefix as its own event before the EOF arrives.
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                    // FIN, not RST: guarantees delivery of everything written
                    // (the truncated-GET case relies on the client seeing all
                    // `early_close_once` bytes, then clean EOF).
                    let _ = sock.shutdown().await;
                });
            }
        });
        (format!("http://{addr}/"), log)
    }

    /// Copy-forward misses (empty active bank) → the part is FETCHED by the
    /// content-address in the (signed) manifest uri: the `sha256:` scheme is
    /// mapped onto the repo blob path for both the size probe and the fetch,
    /// the outer sha is verified while streaming, the inner digest at install,
    /// and the CAS temp is cleaned on success.
    #[tokio::test]
    async fn reconcile_fetches_missing_part_by_content_address() {
        let tmp = tempfile::tempdir().unwrap();
        let images_dir = tmp.path().to_path_buf();
        std::fs::create_dir_all(images_dir.join("vm1/bank_a")).unwrap(); // empty active

        let content = b"vm1 rootfs fetched from the CAS".to_vec();
        // Unencrypted + uncompressed: outer (ciphertext) == inner (plaintext).
        let digest: [u8; 32] = Sha256::digest(&content).into();
        let outer_hex = hex::encode(digest);
        let (base, log) = serve_cas(
            std::collections::HashMap::from([(format!("/blobs/{outer_hex}"), content.clone())]),
            None,
        )
        .await;

        let manifest = detached_manifest_with_uri(
            "rootfs.img",
            &digest,
            content.len() as u64,
            &format!("sha256:{outer_hex}"),
        );
        let backend = vm1_backend(images_dir.clone());
        backend.set_install_source(test_source(base));

        let done = backend
            .reconcile_unpushed(&manifest, 0, 1, Bank::B)
            .await
            .expect("missing active + content-addressed uri → fetch");
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].relative_path, "rootfs.img");
        assert_eq!(done[0].sha256, digest.to_vec());
        assert_eq!(
            std::fs::read(images_dir.join("vm1/bank_b/rootfs.img")).unwrap(),
            content,
        );
        let log = log.lock().unwrap();
        assert!(
            log.iter().any(|l| l == &format!("HEAD /blobs/{outer_hex}")),
            "{log:?}"
        );
        assert!(
            log.iter().any(|l| l == &format!("GET /blobs/{outer_hex}")),
            "{log:?}"
        );
        let leftovers: Vec<_> = std::fs::read_dir(images_dir.join("vm1/cas"))
            .unwrap()
            .collect();
        assert!(leftovers.is_empty(), "CAS temp not cleaned: {leftovers:?}");
    }

    /// Per-part copy-vs-fetch: parts whose active-bank content matches the
    /// manifest digest are copied locally; ONLY the changed part is fetched —
    /// the metered-link litmus (a config-only change never re-downloads the
    /// rootfs).
    #[tokio::test]
    async fn reconcile_copies_matching_parts_and_fetches_only_the_changed_one() {
        use sumo_offboard::image_builder::{
            ComponentSpec as SuitComponentSpec, MultiComponentBuilder,
        };

        let tmp = tempfile::tempdir().unwrap();
        let images_dir = tmp.path().to_path_buf();
        let active = images_dir.join("vm1/bank_a");
        std::fs::create_dir_all(&active).unwrap();

        let kernel = b"kernel bytes the vehicle has".to_vec();
        let rootfs = b"rootfs bytes the vehicle has".to_vec();
        let config_new = b"NEW vm config".to_vec();
        std::fs::write(active.join("kernel"), &kernel).unwrap();
        std::fs::write(active.join("rootfs.img"), &rootfs).unwrap();
        std::fs::write(active.join("vm-config.yaml"), b"OLD vm config").unwrap();

        let d_kernel: [u8; 32] = Sha256::digest(&kernel).into();
        let d_rootfs: [u8; 32] = Sha256::digest(&rootfs).into();
        let d_config: [u8; 32] = Sha256::digest(&config_new).into();
        let config_hex = hex::encode(d_config);
        // Only the changed part exists on the CAS — a request for anything
        // else would 404 and fail the test via the digest/size checks.
        let (base, log) = serve_cas(
            std::collections::HashMap::from([(format!("/blobs/{config_hex}"), config_new.clone())]),
            None,
        )
        .await;

        let key = keygen::generate_signing_key(keygen::ES256).unwrap();
        let spec = |part: &str, d: &[u8; 32], len: usize| SuitComponentSpec {
            id: vec!["vm1".into(), part.into()],
            digest: d.to_vec(),
            size: len as u64,
            uri: format!("sha256:{}", hex::encode(d)),
            encryption_info: None,
        };
        let manifest = MultiComponentBuilder::new()
            .signing_time(1_700_000_000)
            .sequence_number(2)
            .add_component(spec("kernel", &d_kernel, kernel.len()))
            .add_component(spec("rootfs.img", &d_rootfs, rootfs.len()))
            .add_component(spec("vm-config.yaml", &d_config, config_new.len()))
            .build(&key)
            .unwrap();

        let backend = vm1_backend(images_dir.clone());
        backend.set_install_source(test_source(base));

        let done = backend
            .reconcile_unpushed(&manifest, 0, 3, Bank::B)
            .await
            .expect("2 copies + 1 fetch");
        assert_eq!(done.len(), 3);
        let target = images_dir.join("vm1/bank_b");
        assert_eq!(std::fs::read(target.join("kernel")).unwrap(), kernel);
        assert_eq!(std::fs::read(target.join("rootfs.img")).unwrap(), rootfs);
        assert_eq!(
            std::fs::read(target.join("vm-config.yaml")).unwrap(),
            config_new
        );
        // Exactly ONE part hit the network (HEAD + GET on the config blob).
        let log = log.lock().unwrap();
        assert_eq!(log.len(), 2, "{log:?}");
        assert!(log.iter().all(|l| l.ends_with(&config_hex)), "{log:?}");
    }

    /// A CDN serving different bytes behind the content-address is rejected
    /// while streaming (outer sha mismatch) — nothing lands in the target bank.
    #[tokio::test]
    async fn reconcile_rejects_tampered_cdn_content() {
        let tmp = tempfile::tempdir().unwrap();
        let images_dir = tmp.path().to_path_buf();
        std::fs::create_dir_all(images_dir.join("vm1/bank_a")).unwrap();

        let content = b"the bytes T2 signed for".to_vec();
        let digest: [u8; 32] = Sha256::digest(&content).into();
        let outer_hex = hex::encode(digest);
        let (base, _log) = serve_cas(
            std::collections::HashMap::from([(
                format!("/blobs/{outer_hex}"),
                b"SWAPPED cdn object".to_vec(),
            )]),
            None,
        )
        .await;

        let manifest = detached_manifest_with_uri(
            "rootfs.img",
            &digest,
            content.len() as u64,
            &format!("sha256:{outer_hex}"),
        );
        let backend = vm1_backend(images_dir.clone());
        backend.set_install_source(test_source(base));

        let err = backend
            .reconcile_unpushed(&manifest, 0, 1, Bank::B)
            .await
            .expect_err("tampered CDN content must be rejected");
        assert!(matches!(err, BackendError::Internal(_)), "got {err:?}");
        assert!(
            !images_dir.join("vm1/bank_b/rootfs.img").exists(),
            "tampered content must never land in the target bank"
        );
    }

    /// A transport failure mid-blob keeps the resumable `.part` (outside the
    /// bank dirs, so a session restart's bank wipe can't destroy it); the
    /// retry resumes with a Range request and completes.
    #[tokio::test]
    async fn reconcile_fetch_failure_is_retry_safe_and_resumes() {
        let tmp = tempfile::tempdir().unwrap();
        let images_dir = tmp.path().to_path_buf();
        std::fs::create_dir_all(images_dir.join("vm1/bank_a")).unwrap();

        let content: Vec<u8> = (0..4096u32).flat_map(|i| i.to_le_bytes()).collect();
        let digest: [u8; 32] = Sha256::digest(&content).into();
        let outer_hex = hex::encode(digest);
        let (base, log) = serve_cas(
            std::collections::HashMap::from([(format!("/blobs/{outer_hex}"), content.clone())]),
            Some(1000), // first GET truncates after 1000 bytes
        )
        .await;

        let manifest = detached_manifest_with_uri(
            "rootfs.img",
            &digest,
            content.len() as u64,
            &format!("sha256:{outer_hex}"),
        );
        let backend = vm1_backend(images_dir.clone());
        backend.set_install_source(test_source(base));

        backend
            .reconcile_unpushed(&manifest, 0, 1, Bank::B)
            .await
            .expect_err("truncated transfer must fail the first attempt");
        let part = images_dir.join(format!("vm1/cas/cas-{outer_hex}.part"));
        assert!(part.exists(), "resumable partial must persist");
        // Exactly the delivered prefix — serve_cas's post-truncation gap makes
        // the 1000 delivered-then-EOF bytes deterministic.
        assert_eq!(std::fs::metadata(&part).unwrap().len(), 1000);

        let done = backend
            .reconcile_unpushed(&manifest, 0, 1, Bank::B)
            .await
            .expect("retry resumes the partial and completes");
        assert_eq!(done[0].sha256, digest.to_vec());
        assert_eq!(
            std::fs::read(images_dir.join("vm1/bank_b/rootfs.img")).unwrap(),
            content,
        );
        // The retry's GET carried a Range (206 path) — visible as a second GET.
        let log = log.lock().unwrap();
        assert_eq!(
            log.iter().filter(|l| l.starts_with("GET ")).count(),
            2,
            "{log:?}"
        );
    }

    /// The pull route stamps the campaign id via `install_source`: siblings
    /// Join ONE node update transaction, while an unrelated zero-id (push)
    /// start is Mixing-refused. `abort_install` through the adapter resolves
    /// the staging so the node returns to Idle.
    #[tokio::test]
    async fn install_source_session_id_drives_the_node_gate() {
        let tmp = tempfile::tempdir().unwrap();
        let images_dir = tmp.path().to_path_buf();
        let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
        let mut boot = NvBootState::default();
        for set in [BankSet::Vm1, BankSet::Vm2] {
            boot.banks[set.as_index()].active_bank = Bank::A;
            boot.banks[set.as_index()].committed = true;
        }
        nv.write_boot_state(&mut boot).unwrap();
        let nv = Arc::new(Mutex::new(nv));
        let coord = Arc::new(machine_mgr::node_update::NodeCoordinator::new(vec![
            (BankSet::Vm1.as_index(), "vm1".into()),
            (BankSet::Vm2.as_index(), "vm2".into()),
        ]));
        let mk = |set: BankSet| {
            ComponentBackend::with_options(
                set,
                nv.clone(),
                Arc::new(NoopManifest),
                ComponentConfig::default(),
                None,
                Some(images_dir.clone()),
                None,
            )
            .with_node_coordinator(coord.clone())
        };
        let vm1 = mk(BankSet::Vm1);
        let vm2 = mk(BankSet::Vm2);

        let campaign = [7u8; 32];
        let source = |sid| machine_mgr::InstallSource {
            cas_base_url: "http://cas".into(),
            trust_anchor: Vec::new(),
            session_id: Some(sid),
        };
        vm1.set_install_source(source(campaign));
        vm1.ensure_flash_can_start()
            .expect("first campaign member stages");

        // An unrelated zero-id (push-path) start must not mix into the
        // campaign's node transaction…
        let err = vm2
            .ensure_flash_can_start()
            .expect_err("zero id must be Mixing-refused during campaign staging");
        assert!(matches!(err, BackendError::Busy(_)), "got {err:?}");

        // …but the campaign sibling Joins under the same id.
        vm2.set_install_source(source(campaign));
        vm2.ensure_flash_can_start()
            .expect("sibling joins the same node transaction");

        // Adapter-level abort resolves the staging membership (not just the
        // backend session) — the node returns to Idle once both leave.
        use machine_mgr::Component as _;
        let a1 = crate::component_adapter::ComponentAdapter::new(Arc::new(vm1));
        let a2 = crate::component_adapter::ComponentAdapter::new(Arc::new(vm2));
        a1.abort_install(&machine_mgr::FlashId::new("x"))
            .await
            .unwrap();
        a2.abort_install(&machine_mgr::FlashId::new("x"))
            .await
            .unwrap();
        let st = coord.node_update_state(&machine_mgr::node_update::Durable::default(), &[]);
        assert_eq!(st.phase, machine_mgr::node_update::NodePhase::Idle);
    }

    /// Build a fully-provisioned SimHsm (keystore + device `ivd-signing` keypair)
    /// so `finalize_flash`'s seal step can sign. Mirrors `identity_tests`.
    fn provisioned_hsm(
        tag: &str,
    ) -> (
        Arc<Mutex<dyn hsm::HsmProvider>>,
        Arc<dyn hsm::HsmCryptoProvider>,
        PathBuf,
    ) {
        use hsm::payload::*;
        use hsm::HsmProvider;
        use hsm_sim_backend::SimHsm;
        let keystore = std::env::temp_dir().join(format!("component-mgr-copyfwd-ks-{tag}"));
        let _ = std::fs::remove_dir_all(&keystore);
        std::fs::create_dir_all(&keystore).unwrap();
        let hsm = SimHsm::new(keystore.clone());
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
        let crypto: Arc<dyn hsm::HsmCryptoProvider> = Arc::new(SimHsm::new(keystore.clone()));
        (Arc::new(Mutex::new(hsm)), crypto, keystore)
    }

    /// End-to-end brick fix: a 0-payload (manifest-only) push must NOT activate
    /// an empty bank. `finalize_flash` copies the un-pushed component forward from
    /// the active bank, IVD-seals the target, flips NV — so the bank is bootable
    /// (no auto-rollback), not empty.
    #[tokio::test]
    async fn finalize_manifest_only_copies_forward_seals_and_flips_nv() {
        let tmp = tempfile::tempdir().unwrap();
        let images_dir = tmp.path().to_path_buf();

        // Active bank (A) holds the rootfs the manifest-only push declares.
        let content = b"vm1 rootfs already on the vehicle";
        let active = images_dir.join("vm1/bank_a");
        std::fs::create_dir_all(&active).unwrap();
        std::fs::write(active.join("rootfs.img"), content).unwrap();
        let digest: [u8; 32] = Sha256::digest(content).into();

        let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
        let mut boot = NvBootState::default();
        boot.banks[BankSet::Vm1.as_index()].active_bank = Bank::A;
        boot.banks[BankSet::Vm1.as_index()].committed = true;
        nv.write_boot_state(&mut boot).unwrap();
        let nv = Arc::new(Mutex::new(nv));

        let (hsm, crypto, keystore) = provisioned_hsm("finalize");
        let backend = ComponentBackend::with_options(
            BankSet::Vm1,
            nv.clone(),
            Arc::new(NoopManifest),
            ComponentConfig::default(),
            None,
            Some(images_dir.clone()),
            Some(hsm),
        )
        .with_hsm_crypto(crypto);

        // Park a manifest-only session (0 of 1 components pushed) + the Firmware
        // package finalize reads image_meta from (image_sha256 = None, exactly
        // the header-only shape the real manifest-only path produces).
        let manifest = detached_manifest("rootfs.img", &digest, content.len() as u64);
        let validated = ValidatedFirmware {
            bank_set: BankSet::Vm1,
            manifest_type: ManifestType::Firmware,
            image_meta: crate::ota::ImageMeta::default(),
            image_data: Vec::new(),
            version_display: "1.0.0".into(),
            image_sha256: None,
            image_size: None,
            raw_envelope: None,
            streamed_files: Vec::new(),
            signing_time_secs: None,
        };
        backend.packages.lock().unwrap().insert(
            "m1".into(),
            StoredPackage {
                id: "m1".into(),
                validated: validated.clone(),
                status: PackageStatus::Verified,
            },
        );
        *backend.flash_transfer.lock().unwrap() = Some(FlashTransferState {
            transfer_id: "t1".into(),
            package_id: "m1".into(),
            state: FlashState::AwaitingActivation,
            image_size: 0,
            streamed_files: Vec::new(),
        });
        *backend.flash_session.lock().unwrap() = Some(FlashSessionState::AwaitingPayload {
            manifest_bytes: manifest,
            validated,
            next_component: 0,
            total_components: 1,
        });

        // Precondition: target bank is empty (would brick if activated as-is).
        assert!(!images_dir.join("vm1/bank_b/rootfs.img").exists());

        DiagnosticBackend::finalize_flash(&backend)
            .await
            .expect("finalize reconciles the manifest-only push");

        // Target bank now carries the copied rootfs AND a signed IVD manifest.
        assert_eq!(
            std::fs::read(images_dir.join("vm1/bank_b/rootfs.img")).unwrap(),
            content,
            "un-pushed component copied forward from the active bank"
        );
        assert!(
            images_dir.join("vm1/bank_b/ivd-manifest.cbor").exists(),
            "target bank must be IVD-sealed so secure boot / commit accept it"
        );
        assert!(images_dir.join("vm1/bank_b/ivd-signature.bin").exists());
        // Session advanced; NV flipped to the sealed bank in trial mode.
        assert!(matches!(
            *backend.flash_session.lock().unwrap(),
            Some(FlashSessionState::Complete)
        ));
        let s = crate::ota::status(&nv.lock().unwrap(), BankSet::Vm1).unwrap();
        assert_eq!(
            s.active_bank,
            Bank::B,
            "install_precomputed flipped NV to the sealed bank"
        );
        assert!(!s.committed, "banked install enters trial mode");

        let _ = std::fs::remove_dir_all(&keystore);
    }

    /// Pull-path finalize end-to-end: the un-pushed component is FETCHED by
    /// its content-address (the vehicle does NOT have the bytes), the bank
    /// IVD-sealed, NV flipped into trial — the device-side fetch executor
    /// completes the install exactly like the push path would, and the
    /// session-scoped install source is consumed.
    #[tokio::test]
    async fn finalize_manifest_only_fetches_seals_and_flips_nv() {
        let tmp = tempfile::tempdir().unwrap();
        let images_dir = tmp.path().to_path_buf();

        // Active bank exists but does NOT carry the declared content.
        std::fs::create_dir_all(images_dir.join("vm1/bank_a")).unwrap();
        let content = b"vm1 rootfs only the CAS has".to_vec();
        let digest: [u8; 32] = Sha256::digest(&content).into();
        let outer_hex = hex::encode(digest);
        let (base, _log) = serve_cas(
            std::collections::HashMap::from([(format!("/blobs/{outer_hex}"), content.clone())]),
            None,
        )
        .await;

        let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
        let mut boot = NvBootState::default();
        boot.banks[BankSet::Vm1.as_index()].active_bank = Bank::A;
        boot.banks[BankSet::Vm1.as_index()].committed = true;
        nv.write_boot_state(&mut boot).unwrap();
        let nv = Arc::new(Mutex::new(nv));

        let (hsm, crypto, keystore) = provisioned_hsm("finalize-fetch");
        let backend = ComponentBackend::with_options(
            BankSet::Vm1,
            nv.clone(),
            Arc::new(NoopManifest),
            ComponentConfig::default(),
            None,
            Some(images_dir.clone()),
            Some(hsm),
        )
        .with_hsm_crypto(crypto);
        backend.set_install_source(test_source(base));

        let manifest = detached_manifest_with_uri(
            "rootfs.img",
            &digest,
            content.len() as u64,
            &format!("sha256:{outer_hex}"),
        );
        let validated = ValidatedFirmware {
            bank_set: BankSet::Vm1,
            manifest_type: ManifestType::Firmware,
            image_meta: crate::ota::ImageMeta::default(),
            image_data: Vec::new(),
            version_display: "1.0.0".into(),
            image_sha256: None,
            image_size: None,
            raw_envelope: None,
            streamed_files: Vec::new(),
            signing_time_secs: None,
        };
        backend.packages.lock().unwrap().insert(
            "m1".into(),
            StoredPackage {
                id: "m1".into(),
                validated: validated.clone(),
                status: PackageStatus::Verified,
            },
        );
        *backend.flash_transfer.lock().unwrap() = Some(FlashTransferState {
            transfer_id: "t1".into(),
            package_id: "m1".into(),
            state: FlashState::AwaitingActivation,
            image_size: 0,
            streamed_files: Vec::new(),
        });
        *backend.flash_session.lock().unwrap() = Some(FlashSessionState::AwaitingPayload {
            manifest_bytes: manifest,
            validated,
            next_component: 0,
            total_components: 1,
        });

        DiagnosticBackend::finalize_flash(&backend)
            .await
            .expect("finalize fetches the un-pushed component and seals");

        assert_eq!(
            std::fs::read(images_dir.join("vm1/bank_b/rootfs.img")).unwrap(),
            content,
            "un-pushed component fetched from the CAS into the target bank"
        );
        assert!(images_dir.join("vm1/bank_b/ivd-manifest.cbor").exists());
        assert!(images_dir.join("vm1/bank_b/ivd-signature.bin").exists());
        let s = crate::ota::status(&nv.lock().unwrap(), BankSet::Vm1).unwrap();
        assert_eq!(s.active_bank, Bank::B);
        assert!(!s.committed, "banked install enters trial mode");
        assert!(
            backend.install_source.lock().unwrap().is_none(),
            "the session-scoped pull source is consumed by a successful finalize"
        );

        let _ = std::fs::remove_dir_all(&keystore);
    }
}

/// Safe-time floor ratchet (Piece 1): ratchet from a manifest's signed `signing_time`
/// on ANY trust-root-verified manifest — including one rejected for anti-rollback.
#[cfg(test)]
mod time_floor_ratchet_tests {
    use super::*;
    use crate::manifest_provider::{ManifestError, ManifestProvider, ValidatedFirmware};
    use crate::sovd::time_floor::TimeFloor;
    use hsm::HsmProvider;
    use hsm_sim_backend::SimHsm;
    use nv_store::block::MemBlockDevice;
    use nv_store::store::MIN_NV_DEVICE_SIZE;

    struct NoopManifest;
    impl ManifestProvider for NoopManifest {
        fn validate(&self, _d: &[u8], _m: u32) -> Result<ValidatedFirmware, ManifestError> {
            Err(ManifestError::ParseError("unused".into()))
        }
    }

    /// A backend carrying a SimHsm (whose monotonic slot is the safe-time floor).
    /// Returns the backend + a handle to read the floor back.
    fn backend_with_hsm(
        tag: &str,
    ) -> (
        ComponentBackend<MemBlockDevice>,
        Arc<Mutex<dyn HsmProvider>>,
    ) {
        let keystore = std::env::temp_dir().join(format!("cm-floor-{tag}"));
        let _ = std::fs::remove_dir_all(&keystore);
        std::fs::create_dir_all(&keystore).unwrap();
        let hsm: Arc<Mutex<dyn HsmProvider>> = Arc::new(Mutex::new(SimHsm::new(keystore)));

        let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
        nv.write_boot_state(&mut NvBootState::default()).unwrap();
        let backend = ComponentBackend::with_options(
            BankSet::Vm1,
            Arc::new(Mutex::new(nv)),
            Arc::new(NoopManifest),
            ComponentConfig::default(),
            None,
            None,
            Some(hsm.clone()),
        );
        (backend, hsm)
    }

    fn floor(hsm: &Arc<Mutex<dyn HsmProvider>>) -> u64 {
        TimeFloor::read(&*hsm.lock().unwrap()).unwrap()
    }

    #[test]
    fn ratchet_advances_the_floor_and_is_monotonic() {
        let (backend, hsm) = backend_with_hsm("advance");
        assert_eq!(floor(&hsm), 0, "floor starts unraised");

        backend.ratchet_time_floor(1_784_600_000);
        assert_eq!(floor(&hsm), 1_784_600_000, "floor ratchets up to the iat");

        // A LOWER (stale) iat can never rewind the floor — the safety core.
        backend.ratchet_time_floor(1_000_000_000);
        assert_eq!(
            floor(&hsm),
            1_784_600_000,
            "a stale iat is a no-op, never a rewind"
        );

        // A higher iat advances it further.
        backend.ratchet_time_floor(1_784_600_500);
        assert_eq!(floor(&hsm), 1_784_600_500, "a newer iat advances the floor");
    }

    #[test]
    fn rejected_but_trust_root_signed_manifest_still_ratchets_the_floor() {
        // The load-bearing Piece-1 behaviour: a manifest whose signature verified to
        // a trusted root but which we DISCARD for anti-rollback still carried a
        // truthful signed lower bound on real time — the floor must advance from it.
        let (backend, hsm) = backend_with_hsm("reject");
        assert_eq!(floor(&hsm), 0);

        let too_old = ManifestError::RollbackRejected {
            seq: 3,
            min: 5,
            signing_time_secs: Some(1_784_600_000),
        };
        backend.ratchet_time_floor_on_reject(&too_old);
        assert_eq!(
            floor(&hsm),
            1_784_600_000,
            "a rejected-but-trust-root-signed manifest ratchets the floor from its signed iat"
        );
    }

    #[test]
    fn untrusted_or_timeless_rejections_do_not_move_the_floor() {
        let (backend, hsm) = backend_with_hsm("no-time");

        // Bad signature / parse error → no trusted time → no ratchet.
        backend.ratchet_time_floor_on_reject(&ManifestError::SignatureInvalid("bad".into()));
        backend.ratchet_time_floor_on_reject(&ManifestError::DigestMismatch);
        // RollbackRejected but the manifest carried no signing_time → nothing to adopt.
        backend.ratchet_time_floor_on_reject(&ManifestError::RollbackRejected {
            seq: 3,
            min: 5,
            signing_time_secs: None,
        });
        assert_eq!(
            floor(&hsm),
            0,
            "no trusted signed time present → floor untouched"
        );
    }

    // --- Piece 2: the x-sumo-attest-time SOVD operation ---------------------
    use crate::suit_provider::SuitProvider;
    use sovd_core::DiagnosticBackend;
    use sumo_offboard::{keygen, ImageManifestBuilder};

    /// Build a SoftwareAuthority-signed SUIT manifest carrying `signing_time`, plus
    /// a SuitProvider that trusts that key as sw-authority, plus a host (BankSet::Os)
    /// backend with a SimHsm. This is the operator-pushed attest-time artifact.
    fn host_backend_and_signed_manifest(
        tag: &str,
        signing_time: u64,
    ) -> (
        ComponentBackend<MemBlockDevice>,
        Arc<Mutex<dyn HsmProvider>>,
        Vec<u8>,
    ) {
        let key = keygen::generate_signing_key(keygen::ES256).unwrap();
        // A minimal detached (no payload) manifest — attest-time is verify-only.
        let envelope = ImageManifestBuilder::new()
            .signing_time(signing_time)
            .component_id(vec!["host-os".into(), "ifs".into()])
            .sequence_number(1)
            .payload_digest(&[0u8; 32], 0)
            .payload_uri("#firmware".into())
            .build(&key)
            .unwrap();

        // Provider that trusts our signing key as the software authority.
        let provider = SuitProvider::with_factory_authority();
        provider.update_keys(key.public_key_bytes(), None, None);

        let keystore = std::env::temp_dir().join(format!("cm-attest-{tag}"));
        let _ = std::fs::remove_dir_all(&keystore);
        std::fs::create_dir_all(&keystore).unwrap();
        let hsm: Arc<Mutex<dyn HsmProvider>> = Arc::new(Mutex::new(SimHsm::new(keystore)));

        let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
        nv.write_boot_state(&mut NvBootState::default()).unwrap();
        let backend = ComponentBackend::with_options(
            BankSet::Os, // host/device component — where attest-time is advertised
            Arc::new(Mutex::new(nv)),
            Arc::new(provider),
            ComponentConfig::default(),
            None,
            None,
            Some(hsm.clone()),
        );
        (backend, hsm, envelope)
    }

    #[tokio::test]
    async fn attest_time_is_advertised_on_the_host_component_with_an_hsm() {
        let (backend, _hsm, _) = host_backend_and_signed_manifest("advertise", 1_784_600_000);
        let ops = backend.list_operations().await.unwrap();
        assert!(
            ops.iter().any(|o| o.id == ATTEST_TIME_OP_ID),
            "host component with an HSM advertises x-sumo-attest-time"
        );
    }

    #[tokio::test]
    async fn attest_time_verifies_a_signed_manifest_and_ratchets_the_floor() {
        let iat = 1_784_620_143; // the fresh-tower cert not_before from the live repro
        let (backend, hsm, envelope) = host_backend_and_signed_manifest("ratchet", iat);
        assert_eq!(floor(&hsm), 0, "floor starts unraised");

        let exec = backend
            .start_operation(ATTEST_TIME_OP_ID, &envelope)
            .await
            .expect("a sw-authority-signed manifest attests trusted time");
        assert_eq!(exec.status, sovd_core::OperationStatus::Completed);
        assert_eq!(
            floor(&hsm),
            iat,
            "attest-time ratcheted the safe-time floor to the manifest's signed signing_time"
        );
    }

    #[tokio::test]
    async fn attest_time_rejects_a_manifest_not_signed_by_the_trusted_root() {
        // A manifest signed by a DIFFERENT key must not move the floor — the whole
        // security property (independent trusted root, non-circular).
        let (backend, hsm, _good) = host_backend_and_signed_manifest("untrusted", 1_784_620_143);
        let attacker = keygen::generate_signing_key(keygen::ES256).unwrap();
        let forged = ImageManifestBuilder::new()
            .signing_time(9_999_999_999) // far future — the attacker's goal
            .component_id(vec!["host-os".into(), "ifs".into()])
            .sequence_number(1)
            .payload_digest(&[0u8; 32], 0)
            .payload_uri("#firmware".into())
            .build(&attacker)
            .unwrap();

        let res = backend.start_operation(ATTEST_TIME_OP_ID, &forged).await;
        assert!(
            res.is_err(),
            "a manifest not signed by the trusted root is rejected"
        );
        assert_eq!(floor(&hsm), 0, "a forged manifest never moves the floor");
    }
}
